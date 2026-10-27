# Fuzzing wimboot's parsers (host)

Since 0.4.0 wimboot is signed with the BeastBoot Secure Boot key, so a
memory-safety bug reachable from the boot medium (`boot.wim`, the initrd,
the command line) is a potential Secure Boot bypass on every PC that trusts
the key. These harnesses run wimboot's own parser code on the host under
AddressSanitizer and UndefinedBehaviorSanitizer and feed it mutated input.

| target | code under test | input |
|---|---|---|
| `wim`  | `wim.c` (header, lookup table, metadata, directory walk, chunked reads), `lzx.c`, `xca.c`, `huffman.c`, `wimpatch.c` (patched WIM with `index=` and file injection, read in full), `sha1.c` | a whole WIM file |
| `lzx`  | `lzx.c`, `huffman.c` (sizing pass, then a real pass into a buffer of exactly that size, as `wim.c` does) | one compressed chunk |
| `xca`  | `xca.c`, `huffman.c` (same) | one compressed chunk |
| `cpio` | `cpio.c` as patch 0001's LoadFile2 initrd path uses it | an initrd |

Every input is a heap copy of exactly its length, and the WIM read
callback reports any read outside the file (in wimboot that read is a
`memcpy` from the initrd, so it would read other memory).

## Run

```sh
build/wimboot/fuzz/run.sh [--patches N|all] [--time SECONDS] [--workers N] \
    [--from-wim boot.wim] [--targets "wim lzx xca cpio"] OUTDIR
```

It unpacks the pinned source from the wimboot build cache (run `make build`
once), applies the first N patches of `../patches/series` (default all;
`--patches 3` is the code before the memory-safety patches), builds one
binary per target, makes seeds (`mkseeds.py`) and runs N workers per target
for SECONDS each, restarting a worker after each crash. Results:
`OUTDIR/summary.txt` (crashes per target, grouped by kind and first wimboot
frame, by `triage.awk`), crash inputs in `OUTDIR/<target>/crashes/`, logs in
`OUTDIR/<target>/log.*`. Replay one input: `OUTDIR/bin/fuzz_wim FILE`.

`--from-wim` takes LZX chunks from a real WIM (e.g. `sources/boot.wim` of a
Windows ISO) as seeds; without it the LZX target starts from the crafted
WIM seeds' data only. The other seeds are built by `mkseeds.py` (a small
WIM in plain, XPRESS and LZX form with `\Windows\Boot\EFI\bootmgfw.efi` and
`\Windows\System32`, XCA chunks from its own encoder, and newc initrds).
No wimlib needed.

## How

libFuzzer needs clang; this tree builds with gcc, so `engine.c` is a small
AFL-style loop: gcc's `-fsanitize-coverage=trace-pc` reports every basic
block of the code under test, edges go into a 64 KiB bitmap, inputs that
reach new edges join the corpus, and each round applies a stack of havoc
mutations (bit flips, interesting 8/16/32/64-bit values, arithmetic, block
insert/delete/copy, splicing). `shim.c` supplies what the parsers link
against (`die` returns to the harness, 16-bit `wcs*`, the command-line
flags, `vdisk_files`). The wimboot sources are compiled with their own
headers (`-nostdinc -fshort-wchar`, `DEBUG=0` as shipped).

UBSan's `alignment` and `shift-base` checks are off: wimboot reads
unaligned 16-bit words on x86 on purpose, and shifts into the sign bit are
defined by GCC.
