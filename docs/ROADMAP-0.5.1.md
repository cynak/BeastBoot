# 0.5.1 roadmap

## A. Look-alike disks

Two gaps left by the shared-serial fix of 0.5.0 (docs/DISK_TOOLS.md s.1 rule 3:
a serial two attached disks report names neither, and the target's size and
first and last MiB are hashed when the plan is made and compared right before
writing). Both need two disks that report the same serial and size, which is
common with identical USB enclosures. Moved here by the maintainer on
2026-11-13.

### 1. Two blank look-alike disks have the same fingerprint

If the planned target is swapped for another blank disk with the same serial
and size between the plan and the write, the pre-write check cannot tell them
apart: both hash the same.

- Find something that differs between two such disks without writing to them
  (USB port path, bridge and device descriptors, SMART or VPD identity read
  through the bridge), and add it to what the plan records.
- Where nothing differs, say so on the confirmation screen.

### 2. Resuming a stopped clone onto a look-alike disk

A stopped clone or restore is resumed from its saved progress map. The map is
found by source, target path and target serial, so if the target is swapped
for a look-alike and the same copy is started again, it resumes onto the new
disk and skips the areas the map calls finished: the result is not a copy.

- Tie the saved progress to the target itself: either a marker the copy
  writes to the target, or a check of a sample of the areas the map calls
  finished against the source before resuming.
- When the check fails, never resume: offer "Start over", as for a damaged map.
- Tests: unit (swap between stop and resume) and a QEMU run with two disks
  that share a serial.

## B. Certificates from the helper

Since 0.5.0 a component certificate is revoked, and the 0.4.x certificate is
removed, by each user running `mokutil` on an installed Linux
([SECURE_BOOT.md](SECURE_BOOT.md) s.4). Moved here by the maintainer on
2026-11-15.

- A helper menu entry that does both from the stick: list what is enrolled,
  queue the removal of the 0.4.x certificate, queue a revocation that the
  release ships. The firmware's MokManager still asks for confirmation on the
  next start.
- Until then the old certificate stays enrolled until a user removes it
  (accepted for 0.5.0: documented, not enforced).
