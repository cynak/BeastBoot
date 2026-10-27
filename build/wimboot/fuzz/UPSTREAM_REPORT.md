# Draft: private report to iPXE (wimboot) — NOT SENT

To: security contact for iPXE / wimboot (Michael Brown), privately.
Subject: wimboot 2.9.0: stack VLA sized by WIM chunk table (memory corruption from boot.wim)

Hello,

We build a patched wimboot 2.9.0 for beast-boot and found a memory-safety
bug in `src/wim.c` that a crafted `boot.wim` can trigger. As far as we can
tell it is in the Microsoft-signed 2.9.0 release too, so we are reporting
it privately first.

**Where.** `wim_chunk()` takes a chunk's compressed length from the chunk
offset table of the resource, `len = next_offset - offset`, where both
offsets come from `wim_chunk_offset()`. That function checks only that each
offset is `<= zlen`. Nothing checks that offsets increase or that a chunk is
at most `WIM_CHUNK_LEN`. If the stored length differs from the expected
uncompressed length, the compressed data goes into a stack VLA
(`uint8_t zbuf[len];`) and `file->read()` fills it from the WIM.

**Effect.**
- `next_offset < offset`: `len` wraps to nearly 2^64. The VLA moves the
  stack pointer *up* by the wrapped amount, so `zbuf` overlaps the live
  frames. `file->read()` then copies WIM data over them (return addresses
  included) until it faults.
- `next_offset > offset`, up to the resource size: `zbuf` lies `len` bytes
  below the stack. Firmware stacks are small (EDK2: 128 KiB by default) and
  often have no guard page, so the read writes WIM-controlled bytes over
  whatever memory is below the stack. Then the decompressor fails and
  wimboot calls `die()`.

Either way, data from `boot.wim` is written outside wimboot's buffers
before wimboot loads `bootmgfw.efi`. On a PC that trusts a signed wimboot
(Microsoft UEFI CA, or a vendor key such as ours), this looks like a
Secure Boot bypass: someone who can change the boot medium gets code
execution in a signed boot application. We have not written an exploit.
We confirmed the bug on the host with AddressSanitizer: wimboot's `wim.c`
and decompressors, fuzzed with gcc's coverage instrumentation, crash
within seconds (stack overflow in `wim_chunk`, reads outside the WIM file).

**Related findings (lower severity, same fuzzing):**
- `wim_read()`: `offset + len` and `resource->offset + zlen` can overflow.
  For an uncompressed resource, `len > zlen` makes it read past the WIM
  file.
- `xca.c`: `XCA_GET16`/`XCA_GET8` read past the end of the input. A match
  offset larger than the output so far copies from before the output
  buffer.
- `lzx.c`: pretree code 19 takes its second code without a range check.
  `(lengths[i] - code + 17) % 17` goes negative and is stored as a length
  of up to 255. `huffman_alphabet()` then does `huf[bits - 1].freq++` up
  to 254 entries past the 16-entry array, which is a stack write.
- `huffman.c`: an empty alphabet decodes its two placeholder symbols from
  `raw[-2]` and `raw[-1]`.
- `cpio.c`: the name is not checked to fit in the archive or to end in a
  NUL. `strtoul` accepts a sign, so `c_filesize = "-0000010"` gives a
  wrapped length that passes the `cpio_len > len` check.
- `efimain.c`: the command line goes into a VLA sized by `LoadOptionsSize`,
  and `"%ls"` reads until a NUL, past the load options if they have none.

**Fix we ship** (patches attached; valid WIMs decode unchanged):
- Reject decreasing chunk offsets and chunks longer than `WIM_CHUNK_LEN`,
  and use a static `WIM_CHUNK_LEN` buffer instead of the VLA.
- Make the bounds checks in `wim_read()` overflow-safe.
- Bound the XCA reads, check XCA match offsets, range-check the code after
  pretree code 19, and reject lengths over `HUFFMAN_BITS`.
- In the CPIO parser, require strict hex fields, a terminated name and
  data that fits.
- Cap the command-line copy.

We plan to release our fixed build on <date>. We are glad to coordinate
the timing with you, and with an SBAT generation bump for `wimboot` if you
want one. Our builds carry their own vendor SBAT line
(`wimboot.beastboot`).

Regards,
<name>, beast-boot
