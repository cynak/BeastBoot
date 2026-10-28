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
binary per target, makes seeds (`mkseeds.py`) and fuzzes the targets one
after another, N workers (default 2) for SECONDS each, so at most N fuzz
processes run at once; a worker restarts after each crash. Results:
`OUTDIR/summary.txt` (crashes per target, grouped by kind and first wimboot
frame, by `triage.awk`), crash inputs in `OUTDIR/<target>/crashes/`, logs in
`OUTDIR/<target>/log.*`. Replay one input: `OUTDIR/bin/fuzz_wim FILE`.

### Memory caps

Every worker is capped, so neither a harness leak nor an input that makes
wimboot allocate a lot can take the machine down:

| cap | default | override | on hit |
|---|---|---|---|
| ASan `hard_rss_limit_mb` | 2048 | `BB_FUZZ_RSS_MB` | ASan aborts the process |
| ASan `max_allocation_size_mb` (with `allocator_may_return_null=0`) | 1024 | `BB_FUZZ_ALLOC_MB` | ASan reports the allocation and aborts |
| systemd user scope `MemoryMax` (`MemorySwapMax=0`), when `systemd-run --user` works | 4G | `BB_FUZZ_SCOPE_MAX` | kernel kills the worker (SIGKILL) |

The ASan limits act first, inside the process; the scope is only a
backstop for memory ASan does not track (a cgroup kill also shows a desktop
notification). Each hit is a finding, not a silent restart: the input is
saved in `crashes/` (by the death callback, or by run.sh from the
`-current` copy the engine keeps of the running input, `killed-*` for a
scope kill) and `summary.txt` lists it as `memory limit: ...`.

A 2026-10-27 run without these caps grew one `fuzz_wim` worker to 33 GB:
`fuzz_wim.c` leaked its read buffer whenever `patch_wim()` rejected the
WIM, because `die()` longjmps past `free()`. Fixed in the harness (the
buffer is freed after the jump); wimboot's parsers allocate nothing.

`--from-wim` takes LZX chunks from a real WIM (e.g. `sources/boot.wim` of a
Windows ISO, `7z e ISO sources/boot.wim`) as seeds, for the `lzx` target and
as small LZX WIMs for the `wim` target. Use it: without it there are no LZX
seeds and the fuzzer barely gets into the LZX decoder (19 edges in 2
minutes; run.sh warns). The other seeds are built by `mkseeds.py` (a small
WIM in plain and XPRESS form with `\Windows\Boot\EFI\bootmgfw.efi` and
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
