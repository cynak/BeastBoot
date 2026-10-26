"""Disk tools: recovery and cloning, RAID-aware (docs/DISK_TOOLS.md).

Module ownership (each part implements only its own modules, against model.py):

  discover.py   scan(ctx) -> Inventory: disks, partitions, stacks, volumes
  guard.py      protect_all(ctx), reapply(ctx), make_writable(ctx, disk), status(ctx)
  health.py     read(ctx, disk) -> Health (smartctl --json; NVMe via smartctl too)
  probe.py      stack detection (blkid, mdadm --examine, LVM/LUKS/BitLocker/btrfs/ZFS/LDM
                signatures, Storage Spaces GPT type, "may be an AMD RAID member")
  assemble.py   start(ctx, stack) -> list[Volume]; stop(ctx, stack); read-only only
  overlay.py    create(ctx, devices) -> list[str]; remove(ctx, overlays); usage(ctx)
  reconstruct.py detect(ctx, devices) -> list[Candidate]; build(ctx, devices, cand) -> Volume;
                validate(ctx, volume) -> float; teardown(ctx, volume)
  copy.py       plan(ctx, inv, kind, source, target, **opts) -> CopyPlan;
                run(ctx, plan, on_progress, should_stop) -> CopyResult

`ctx` is beastnet.context.Context (runner, reporter, paths). Every external
command goes through ctx.system/runner so tests can stub it.
"""
