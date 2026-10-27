"""Start a stack read-only so its data can be copied or mounted, and stop it again.

Only read-only options exist here: every command goes through ``check_argv``,
an allow-list of exact command shapes (mdadm --assemble --readonly, LVM
activation with a read-only volume list on overlays, cryptsetup open --readonly,
zpool import -o readonly=on, ...). After each start the new dm/md devices are
checked to be read-only in sysfs; if one is not, the stack is stopped and the
start fails. The guard is re-applied after every start.

Read-only is not enough on its own: md rewrites an internal write-intent bitmap
when it loads and stops an array (also a read-only one; BLKROSET on the members
only makes the kernel warn), and LVM raid/mirror/cache/thin targets write when
they are activated. So:

* md (0.90/1.x) and DDF arrays start on dm-snapshot overlays of their members
  (``overlay.create`` with OVERLAY_PREFIX, COW in RAM): whatever the kernel
  writes lands in RAM. IMSM cannot (mdadm finds IMSM members by the disk's
  serial number, which a dm device does not report), so IMSM volumes start on
  the members, and only when ``mdadm --examine`` shows no bitmap, PPL/journal
  or migration: with external metadata the kernel never writes the metadata
  itself (mdmon does, and it never runs here), and a read-only array without
  those features gets no other write.
* LVM: only VGs whose LVs are all linear or striped (LVM_PLAIN_SEGTYPES) are
  activated, on overlays of the PVs (``--devices`` lists only the overlays).
  raid*, mirror, cache*, thin*, writecache, integrity, vdo and snapshot LVs
  write on activation (resync marks, log headers, cache/thin metadata, a
  pending snapshot merge), so their VGs are refused: image the PVs instead.
* Windows dynamic disks (LDM) are detected only: image each disk.

Passphrases go to the tool's stdin only: never into argv, the environment,
the logs or an error text.
"""

from __future__ import annotations

import json
import os
import re
from subprocess import CompletedProcess

from ..context import Context
from ..errors import ASSEMBLE, BeastNetError
from . import guard, overlay
from .discover import (
    assembled_volumes,
    block_names,
    is_md_container,
    mounted_devices,
    read_int,
    read_text,
    slaves_of,
)
from .model import Stack, StackKind, StackState, Support, Volume, VolumeKind
from .probe import TOOL_ENV, intel_raid_present

ARC_MAX_CAP = 256 << 20  # ZFS ARC ceiling (bytes): the helper runs from RAM
OVERLAY_PREFIX = "bbro_"  # dm names of the overlays read-only assembly uses (reconstruction: "bbov_")
OVERLAY_KINDS = (StackKind.MD, StackKind.DDF)  # md kinds started on overlays (not IMSM: see above)
LVM_PLAIN_SEGTYPES = frozenset({"linear", "striped"})  # the only LV types LVM starts without writing


# -- the command filter -------------------------------------------------------------------
# Allow-lists of exact command shapes: anything not listed is refused.

_MDADM_DENY = {"--force", "-f", "--update", "-U", "--add", "-a", "--add-spare", "--re-add", "--grow", "-G",
               "--create", "-C", "--zero-superblock", "--fail", "--set-faulty", "--remove", "-r", "--assume-clean",
               "--backup-file", "--invalid-backup", "--readwrite", "-w", "--add-journal", "--replace", "--manage",
               "--build", "-B", "--action", "--wait-clean", "--kill-subarray", "--update-subarray", "--wait", "-W",
               "--grow-continue", "--continue", "--monitor", "-F", "--write-mostly"}
_MDADM_SHOW = {"--scan", "-s", "--brief", "-b", "--export", "-Y", "--verbose", "-v", "--config=none"}
_CRYPT_DENY = {"--allow-discards", "--persistent", "--refresh", "--header", "--force-password"}
_LVM_REPORT_OPTS = {"--reportformat", "-o", "--options", "--select", "-S", "--devices", "--config", "--units"}
_LVM_REPORT_FLAGS = {"-a", "--all", "--noheadings", "--nosuffix", "--segments", "--readonly"}
_LVM_VGCHANGE_OPTS = {"--devices", "--select", "--config"}
_ZPOOL_DENY = {"-f", "-F", "-m", "-X", "-T", "-D", "-a"}
_RO_LIST = re.compile(r'read_only_volume_list\s*=\s*\[\s*"[^"\s]+"')


def _refuse(text: str) -> BeastNetError:
    return BeastNetError(ASSEMBLE, text, "Disk tools only open things read-only; this option could write to a source.")


def _split(args: list[str], with_value: set[str]) -> tuple[list[str], dict[str, str], list[str]]:
    """(flags, {option: value}, positionals). Raises for an option given twice or without a value."""
    flags, opts, pos = [], {}, []
    i = 0
    while i < len(args):
        a = args[i]
        if a in with_value:
            if i + 1 >= len(args) or a in opts:
                raise _refuse(f"{a} needs exactly one value")
            opts[a] = args[i + 1]
            i += 2
            continue
        (flags if a.startswith("-") else pos).append(a)
        i += 1
    return flags, opts, pos


def _check_mdadm(args: list[str]) -> None:
    bad = [a for a in args if a in _MDADM_DENY or a.split("=", 1)[0] in _MDADM_DENY]
    if bad:
        raise _refuse(f"mdadm {bad[0]} is not allowed")
    if not args:
        raise _refuse("mdadm needs an allowed mode")
    flags = [a for a in args if a.startswith("-")]
    pos = [a for a in args if not a.startswith("-")]
    mode = args[0]
    if not all(p.startswith("/") for p in pos):
        raise _refuse("mdadm: only device paths may follow the options")
    if mode == "--assemble":
        # mdadm --assemble --readonly --config=none [--run] <md> <members...>
        if "--readonly" not in flags:
            raise _refuse("arrays must start with --readonly")
        if set(flags) - {"--assemble", "--readonly", "--config=none", "--run"} or len(pos) < 2:
            raise _refuse("mdadm --assemble: only --readonly --config=none [--run] <md> <members>")
    elif mode == "--incremental":
        # --incremental takes no --readonly: _start_md only runs it on a started container,
        # after setting md's start_ro=1, then sets every volume read-only.
        if sorted(flags) != sorted(["--incremental", "--run", "--config=none"]) or len(pos) != 1:
            raise _refuse("mdadm --incremental is only used to start a container's volumes")
    elif mode in ("--readonly", "--stop"):
        if flags != [mode] or len(pos) != 1:
            raise _refuse(f"mdadm {mode} takes exactly one md device")
    elif mode in ("--examine", "-E", "--detail", "-D"):
        if set(flags) - _MDADM_SHOW - {mode}:
            raise _refuse("mdadm: only display options with --examine/--detail")
    else:
        raise _refuse(f"mdadm {mode} is not an allowed mode")


def _check_lvm(args: list[str]) -> None:
    if not args or args[0] not in ("pvs", "vgs", "lvs", "vgchange"):
        raise _refuse("lvm: only pvs, vgs, lvs and vgchange -a are allowed")
    sub, rest = args[0], args[1:]
    if sub == "vgchange":
        flags, opts, pos = _split(rest, _LVM_VGCHANGE_OPTS)
        if sorted(flags) not in (["-ay"], ["-an"]) or len(pos) > 1 or ("--select" in opts) == bool(pos):
            raise _refuse("vgchange is only used as: -ay|-an (<vg> | --select vg_uuid=...) --config ... --devices ...")
        cfg = opts.get("--config", "")
        if "-ay" in flags:
            if not _RO_LIST.search(cfg) or "metadata_read_only=1" not in cfg:
                raise _refuse("LVM must activate read-only, with read_only_volume_list naming the VG")
            devs = [d for d in opts.get("--devices", "").split(",") if d]
            if not devs or not all(d.startswith("/dev/mapper/" + OVERLAY_PREFIX) for d in devs):
                raise _refuse("LVM may only activate on the RAM overlays of the physical volumes (--devices)")
    else:
        flags, opts, pos = _split(rest, _LVM_REPORT_OPTS)
        if set(flags) - _LVM_REPORT_FLAGS:
            raise _refuse(f"lvm {sub}: option not allowed")
    if "--select" in opts and not re.fullmatch(r"vg_uuid=[A-Za-z0-9-]+", opts["--select"]):
        raise _refuse("lvm: --select only by vg_uuid")


def check_argv(argv: list[str]) -> None:
    """Raise BeastNetError(assemble) for a command that is not strictly read-only."""
    if not argv:
        raise _refuse("empty command")
    prog, args = os.path.basename(argv[0]), argv[1:]
    if prog == "mdadm":
        _check_mdadm(args)
    elif prog == "cryptsetup":
        if not args or args[0] not in ("open", "close", "status"):
            raise _refuse("cryptsetup: only open, close and status are allowed")
        if any(a in _CRYPT_DENY or a.startswith("--allow-discards") for a in args):
            raise _refuse("cryptsetup option not allowed")
        if args[0] == "open" and "--readonly" not in args:
            raise _refuse("cryptsetup open needs --readonly")
        if args[0] == "open" and "--type" in args and args[args.index("--type") + 1] not in ("luks", "bitlk"):
            raise _refuse("only LUKS and BitLocker volumes can be opened")
    elif prog == "lvm":
        _check_lvm(args)
    elif prog == "dmsetup":
        if not args or args[0] not in ("mknodes", "info", "ls", "table", "status"):
            raise _refuse("dmsetup: this subcommand is not allowed")
    elif prog == "zpool":
        if not args or args[0] not in ("import", "export", "list", "version"):
            raise _refuse("zpool: this subcommand is not allowed")
        if args[0] == "import":
            if any(a in _ZPOOL_DENY for a in args):
                raise _refuse("zpool import option not allowed (no -f, -F, -m, -X, -T, -D)")
            if "readonly=on" not in args or "-N" not in args or "cachefile=none" not in args:
                raise _refuse("pools must import with -o readonly=on -N -o cachefile=none")
    elif prog == "mdev":
        if args != ["-s"]:
            raise _refuse("mdev: only -s is allowed")
    elif prog == "modprobe":
        if not args or args[0] != "zfs":
            raise _refuse("modprobe: only zfs is allowed")
    else:
        raise _refuse(f"{prog} is not an allowed assembly tool")


def _run(ctx: Context, argv: list[str], *, env: dict | None = None, input: str | None = None,
         timeout: float = 120) -> CompletedProcess:
    check_argv(argv)
    return ctx.system.runner.run(argv, env={**TOOL_ENV, **(env or {})}, input=input, timeout=timeout)


def _why(cp: CompletedProcess) -> str:
    for line in ((cp.stderr or "") + "\n" + (cp.stdout or "")).splitlines():
        if line.strip():
            return line.strip()[:200]
    return f"exit code {cp.returncode}"


# -- helpers ------------------------------------------------------------------------------

def _tool(ctx: Context, tool: str, arg: str = "--version") -> bool:
    return ctx.system.runner.run([tool, arg], timeout=15).returncode not in (126, 127)


def _names(ctx: Context) -> set[str]:
    return set(block_names(ctx.paths.sys))


def _mknodes(ctx: Context) -> None:
    _run(ctx, ["dmsetup", "mknodes"], timeout=30)
    _run(ctx, ["mdev", "-s"], timeout=60)


def _free_md(ctx: Context, count: int) -> list[str]:
    out, n = [], 127
    used = _names(ctx)
    while len(out) < count and n >= 0:
        if f"md{n}" not in used and not os.path.exists(os.path.join(ctx.paths.dev, f"md{n}")):
            out.append(f"md{n}")
        n -= 1
    return out


def _members(stack: Stack) -> list[str]:
    return [m.device for m in stack.members if m.state not in ("spare", "missing", "faulty")]


def _ro(ctx: Context, name: str) -> bool:
    return read_int(os.path.join(ctx.paths.sys, "block", name, "ro"), 0) == 1


def _top_level(ctx: Context, names: set[str]) -> list[str]:
    """New devices that no other new device sits on (hides LVM/thin internals)."""
    out = []
    for n in sorted(names):
        try:
            holders = set(os.listdir(os.path.join(ctx.paths.sys, "block", n, "holders")))
        except OSError:
            holders = set()
        if not holders & names:
            out.append(n)
    return out


def _volumes(ctx: Context, names: list[str], stack: Stack, kind: VolumeKind | None = None) -> list[Volume]:
    vols = [v for v in assembled_volumes(ctx) if v.id in names]
    for v in vols:
        v.from_stack = stack.id
        v.readonly = True
        if kind is not None:
            v.kind = kind
        v.path = guard.ensure_node(ctx, v.id)
    return vols


def _fail(ctx: Context, stack: Stack, text: str, hint: str = "") -> BeastNetError:
    return BeastNetError(ASSEMBLE, text, hint)


def _verify_ro(ctx: Context, names: list[str]) -> list[str]:
    return [n for n in names if not _ro(ctx, n)]


# -- start --------------------------------------------------------------------------------

def start(ctx: Context, stack: Stack, *, passphrase: str | None = None) -> list[Volume]:
    """Start ``stack`` read-only and return its volumes. Emits `assemble ok|fail`.
    Raises BeastNetError(assemble) when it cannot be started read-only."""
    try:
        vols = _start(ctx, stack, passphrase)
    except BeastNetError as e:
        ctx.reporter.emit("assemble fail", f"id={stack.id}", f"code={e.code}")
        raise
    guard.reapply(ctx)
    for v in vols:
        ctx.reporter.emit("assemble ok", f"id={stack.id}", f"dev={v.path}", "ro=1")
    return vols


def _start(ctx: Context, stack: Stack, passphrase: str | None) -> list[Volume]:
    if stack.kind == StackKind.LDM:
        raise _fail(ctx, stack, "Windows dynamic disks are not opened by this version of Disk tools",
                    "Image each disk instead (an image holds the whole dynamic disk).")
    if stack.support == Support.NEEDS_PACK:
        raise _fail(ctx, stack, "needs the ZFS pack", "Install the ZFS pack from the desktop app, then try again.")
    if stack.support != Support.ASSEMBLE:
        raise _fail(ctx, stack, f"{stack.kind.value} cannot be opened by a Linux tool",
                    "Use reconstruction, or image each member disk.")
    if stack.state == StackState.INCOMPLETE:
        raise _fail(ctx, stack, "too many members are missing", "Image the members that are there, or try reconstruction.")
    present = _members(stack)
    if not present:
        raise _fail(ctx, stack, "the stack has no usable members")
    for dev in present:
        if not os.path.exists(dev):
            raise _fail(ctx, stack, f"{dev} is not there")
    guard.reapply(ctx)  # members read-only before anything opens them
    k = stack.kind
    if k in (StackKind.MD, StackKind.IMSM, StackKind.DDF):
        return _start_md(ctx, stack, present)
    if k == StackKind.LVM:
        return _start_lvm(ctx, stack)
    if k in (StackKind.LUKS, StackKind.BITLOCKER):
        return _start_crypt(ctx, stack, present[0], passphrase)
    if k == StackKind.ZFS:
        return _start_zfs(ctx, stack)
    if k == StackKind.BTRFS:
        return _start_btrfs(ctx, stack, present)
    raise _fail(ctx, stack, f"{k.value} cannot be opened by a Linux tool", "Use reconstruction, or image each member disk.")


def _md_env(ctx: Context) -> dict[str, str]:
    # No mdmon: it would take over IMSM/DDF volumes and write their metadata.
    env = {"MDADM_NO_UDEV": "1", "MDADM_NO_MDMON": "1"}
    if not intel_raid_present(ctx):
        env["IMSM_NO_PLATFORM"] = "1"
    return env


def ensure_start_ro(ctx: Context) -> None:
    """md's start_ro=1: every array the kernel starts from now on is read-auto (no
    resync, no superblock write) until it is set read-only. BLKROSET on the members
    does not stop md's own writes, so this must hold before any assembly."""
    p = os.path.join(ctx.paths.sys, "module", "md_mod", "parameters", "start_ro")
    try:
        if read_text(p) != "1":
            with open(p, "w") as f:
                f.write("1")
    except OSError as e:
        raise BeastNetError(ASSEMBLE, f"cannot make md start arrays read-only: {e.strerror}") from None
    if read_text(p) != "1":
        raise BeastNetError(ASSEMBLE, "md does not start arrays read-only (start_ro is not 1)")


def _keep_guarded(*names: str) -> None:
    """Assembly overlays are not exempted from the guard: their nodes stay BLKROSET too
    (the kernel only warns, so md and dm writes still reach the COW in RAM)."""


def _overlays(ctx: Context, stack: Stack, devices: list[str]) -> list[str]:
    """RAM overlays (dm-snapshot, COW in tmpfs) over ``devices``, in the same order."""
    try:
        paths = overlay.create(ctx, devices, prefix=OVERLAY_PREFIX, exempt=_keep_guarded)
    except BeastNetError as e:
        raise _fail(ctx, stack, f"could not put RAM overlays over the members: {e.text}",
                    "Free some memory, or image each member disk instead.") from None
    try:
        guard.reapply(ctx)
    except BaseException:
        _quiet_drop(ctx, stack, devices)
        raise
    return paths


def _drop_overlays(ctx: Context, stack: Stack, devices: list[str] | None = None) -> None:
    devs = devices if devices is not None else [m.device for m in stack.members]
    mine = overlay.owned(ctx, OVERLAY_PREFIX, devs)
    if mine:
        try:
            overlay.remove(ctx, [o.path for o in mine], unexempt=_keep_guarded)
        except BeastNetError as e:
            raise _fail(ctx, stack, e.text) from None


def _quiet_drop(ctx: Context, stack: Stack, devices: list[str]) -> None:
    """Cleanup after a failed start: the start's own error is the one to report."""
    try:
        _drop_overlays(ctx, stack, devices)
    except BeastNetError:
        pass


_IMSM_UNSAFE = re.compile(r"bitmap|\bppl\b|journal", re.I)


def _check_imsm(ctx: Context, stack: Stack, members: list[str], env: dict[str, str]) -> None:
    """IMSM starts on the members themselves (see OVERLAY_KINDS), so only volumes the
    kernel cannot write to while read-only: no write-intent bitmap, no PPL or journal
    (the RWH policy), no migration (a reshape mdadm would continue)."""
    for dev in members:
        cp = _run(ctx, ["mdadm", "--examine", dev], env=env, timeout=60)
        out = cp.stdout or ""
        if cp.returncode != 0 or not re.search(r"Intel Raid ISM|imsm", out, re.I):
            raise _fail(ctx, stack, f"cannot read the Intel RAID metadata on {dev}: {_why(cp)}")
        policies = re.findall(r"RWH Policy\s*:\s*(.+)", out)
        migrate = [m.strip().lower() for m in re.findall(r"Migrate State\s*:\s*(.+)", out)]
        if any(p.strip().lower() != "off" for p in policies) or _IMSM_UNSAFE.search(out):
            raise _fail(ctx, stack, "this Intel RAID volume keeps a write-intent bitmap or a write journal (PPL), "
                        "which the kernel updates even when the volume is opened read-only",
                        "Image each member disk instead.")
        if any(m not in ("idle", "") for m in migrate):
            raise _fail(ctx, stack, "this Intel RAID volume is in the middle of a migration (rebuild, reshape "
                        "or initialization), which mdadm would continue", "Image each member disk instead.")


def _start_md(ctx: Context, stack: Stack, members: list[str]) -> list[Volume]:
    ensure_start_ro(ctx)
    env = _md_env(ctx)
    if stack.kind in OVERLAY_KINDS:
        devices = _overlays(ctx, stack, members)
    else:
        _check_imsm(ctx, stack, members, env)
        devices = members
    before = _names(ctx)
    try:
        return _assemble_md(ctx, stack, devices, env, before)
    except BaseException:
        _stop_new(ctx, before)
        if stack.kind in OVERLAY_KINDS:
            _quiet_drop(ctx, stack, members)
        raise


def _assemble_md(ctx: Context, stack: Stack, devices: list[str], env: dict[str, str],
                 before: set[str]) -> list[Volume]:
    external = stack.kind in (StackKind.IMSM, StackKind.DDF)
    nodes = _free_md(ctx, 1)
    if not nodes:
        raise _fail(ctx, stack, "no free md device number")
    base = ["mdadm", "--assemble", "--readonly", "--config=none"]
    if stack.state == StackState.DEGRADED and not external:
        base.append("--run")  # start a degraded array; never --force
    cp = _run(ctx, [*base, os.path.join(ctx.paths.dev, nodes[0]), *devices], env=env)
    if cp.returncode != 0:
        raise _fail(ctx, stack, f"mdadm could not start the array: {_why(cp)}")
    if external:  # the container is up; start the volumes inside it, still read-only
        cp = _run(ctx, ["mdadm", "--incremental", "--run", "--config=none",
                        os.path.join(ctx.paths.dev, nodes[0])], env=env)
        if cp.returncode != 0:
            raise _fail(ctx, stack, f"mdadm could not start the volumes: {_why(cp)}")
    _mknodes(ctx)
    new = _names(ctx) - before
    arrays = [n for n in sorted(new) if n.startswith("md") and not is_md_container(ctx.paths.sys, n)]
    if not arrays:
        raise _fail(ctx, stack, "mdadm started nothing")
    for n in arrays:
        state = read_text(os.path.join(ctx.paths.sys, "block", n, "md", "array_state"))
        if state in ("read-auto", "clean", "active", "inactive"):
            _run(ctx, ["mdadm", "--readonly", os.path.join(ctx.paths.dev, n)], env=env)
            state = read_text(os.path.join(ctx.paths.sys, "block", n, "md", "array_state"))
        if state != "readonly":
            raise _fail(ctx, stack, f"{n} did not start read-only (state '{state or 'unknown'}')")
    return _volumes(ctx, arrays, stack, VolumeKind.MD)


def _stop_new(ctx: Context, before: set[str]) -> None:
    """Undo a failed start: stop every md device that appeared (volumes before containers)."""
    new = _names(ctx) - before
    for n in sorted(new, key=lambda x: is_md_container(ctx.paths.sys, x) if x.startswith("md") else False):
        if n.startswith("md"):
            _run(ctx, ["mdadm", "--stop", os.path.join(ctx.paths.dev, n)], env={"MDADM_NO_UDEV": "1"}, timeout=60)


def lvm_config(vg: str) -> str:
    return ("global{metadata_read_only=1} activation{udev_sync=0 udev_rules=0 verify_udev_operations=0 "
            f'read_only_volume_list=["{vg}"]' + "}")


def vg_select(stack: Stack) -> list[str]:
    """Name a VG by UUID: two disks can carry VGs with the same name."""
    uuid = stack.id.split(":", 1)[1] if ":" in stack.id else ""
    if re.fullmatch(r"[A-Za-z0-9-]{38}", uuid):
        return ["--select", f"vg_uuid={uuid}"]
    return [stack.name]


def _lvm_segtypes(ctx: Context, stack: Stack, devices: list[str]) -> set[str]:
    """Segment types of every LV of the VG (hidden ones too), read from ``devices`` only."""
    cp = _run(ctx, ["lvm", "lvs", "-a", "--reportformat", "json", "-o", "lv_name,segtype",
                    "--devices", ",".join(devices), *vg_select(stack), "--config", lvm_config(stack.name)])
    try:
        rows = json.loads(cp.stdout or "")["report"][0]["lv"]
        types = {str(r["segtype"]).strip() for r in rows}
    except (ValueError, KeyError, IndexError, TypeError):
        rows, types = None, set()
    if cp.returncode == 0 and rows == []:
        raise _fail(ctx, stack, f"'{stack.name}' has no logical volumes to open")
    if cp.returncode != 0 or not types:
        raise _fail(ctx, stack, f"could not read the logical volumes of '{stack.name}': {_why(cp)}",
                    "Image the physical volumes instead.")
    return types


def _start_lvm(ctx: Context, stack: Stack) -> list[Volume]:
    vg = stack.name
    if not vg or re.search(r'["\s\\]', vg):
        raise _fail(ctx, stack, "the volume group has no usable name")
    pvs = _members(stack)
    other = sorted(_lvm_segtypes(ctx, stack, pvs) - LVM_PLAIN_SEGTYPES)
    if other:
        raise _fail(ctx, stack, f"'{vg}' has {', '.join(other)} logical volumes; LVM writes to the disks "
                    "when it starts those, even read-only", "Image the physical volumes instead.")
    ovl = _overlays(ctx, stack, pvs)
    before = _names(ctx)
    act = ["lvm", "vgchange", "-ay", "--devices", ",".join(ovl), *vg_select(stack), "--config", lvm_config(vg)]
    deact = ["lvm", "vgchange", "-an", "--devices", ",".join(ovl), *vg_select(stack), "--config", lvm_config(vg)]
    try:
        cp = _run(ctx, act)
        if cp.returncode != 0:
            raise _fail(ctx, stack, f"LVM could not activate '{vg}': {_why(cp)}")
        _mknodes(ctx)
        new = {n for n in _names(ctx) - before if n.startswith("dm-")}
        bad = _verify_ro(ctx, sorted(new))
        if bad:
            raise _fail(ctx, stack, f"{', '.join(bad)} was not activated read-only")
        top = _top_level(ctx, new)
        if not top:
            raise _fail(ctx, stack, f"'{vg}' has no logical volumes to open")
        return _volumes(ctx, top, stack, VolumeKind.LV)
    except BaseException:
        _run(ctx, deact)
        _quiet_drop(ctx, stack, pvs)
        raise


def crypt_name(stack: Stack) -> str:
    return "bb" + re.sub(r"[^A-Za-z0-9]", "", stack.id.split(":", 1)[-1])[:14]


def _start_crypt(ctx: Context, stack: Stack, member: str, passphrase: str | None) -> list[Volume]:
    if not passphrase:
        raise _fail(ctx, stack, "a passphrase or recovery key is needed",
                    "Without it, image the encrypted device as it is.")
    typ = "luks" if stack.kind == StackKind.LUKS else "bitlk"
    if not _tool(ctx, "cryptsetup"):
        raise _fail(ctx, stack, "cryptsetup is not in this helper")
    before = _names(ctx)
    name = crypt_name(stack)
    cp = _run(ctx, ["cryptsetup", "open", "--readonly", "--type", typ, member, name], input=passphrase + "\n")
    if cp.returncode != 0:
        if cp.returncode == 2:
            raise _fail(ctx, stack, "the passphrase or recovery key was not accepted")
        raise _fail(ctx, stack, f"cryptsetup could not open it: {_why(cp)}")
    _mknodes(ctx)
    new = {n for n in _names(ctx) - before if n.startswith("dm-")}
    bad = _verify_ro(ctx, sorted(new))
    if bad or not new:
        _run(ctx, ["cryptsetup", "close", name])
        raise _fail(ctx, stack, "the unlocked device was not read-only" if bad else "nothing was unlocked")
    return _volumes(ctx, _top_level(ctx, new), stack, VolumeKind.CRYPT)


def arc_max(ctx: Context) -> int:
    """ZFS ARC ceiling: 1/8 of RAM, at most 256 MiB, at least 32 MiB."""
    mem = 0
    for line in read_text(os.path.join(ctx.paths.proc, "meminfo")).splitlines():
        if line.startswith("MemTotal:"):
            mem = int(line.split()[1]) * 1024
    return max(32 << 20, min(ARC_MAX_CAP, mem // 8 if mem else ARC_MAX_CAP))


def _start_zfs(ctx: Context, stack: Stack) -> list[Volume]:
    if not _tool(ctx, "zpool", "version"):
        raise _fail(ctx, stack, "needs the ZFS pack", "Install the ZFS pack from the desktop app, then try again.")
    cap = arc_max(ctx)
    param = os.path.join(ctx.paths.sys, "module", "zfs", "parameters", "zfs_arc_max")
    if os.path.exists(param):
        try:
            with open(param, "w", encoding="ascii") as f:
                f.write(str(cap))
        except OSError:
            pass
    else:
        _run(ctx, ["modprobe", "zfs", f"zfs_arc_max={cap}"], timeout=60)
    guid = stack.id.split(":", 1)[-1]
    target = guid if guid.isdigit() else stack.name
    if not target:
        raise _fail(ctx, stack, "the pool has no name or id")
    cp = _run(ctx, ["zpool", "import", "-o", "readonly=on", "-N", "-o", "cachefile=none", "-d", ctx.paths.dev, target])
    if cp.returncode != 0:
        raise _fail(ctx, stack, f"zpool could not import it read-only: {_why(cp)}",
                    "Features the bundled OpenZFS lacks cannot be read; image the member disks instead.")
    name = stack.name or target
    return [Volume(id=name, path=f"zpool:{name}", kind=VolumeKind.ZFS_DATASET, size=0, readonly=True,
                   from_stack=stack.id, disk_ids=sorted({m.disk_id for m in stack.members}))]


def _dev_size(ctx: Context, path: str) -> int:
    name = os.path.basename(path)
    sysr = ctx.paths.sys
    cands = [os.path.join(sysr, "class", "block", name, "size"), os.path.join(sysr, "block", name, "size")]
    cands += [os.path.join(sysr, "block", d, name, "size") for d in block_names(sysr)]
    for c in cands:
        if os.path.exists(c):
            return read_int(c) * 512
    return 0


def _start_btrfs(ctx: Context, stack: Stack, members: list[str]) -> list[Volume]:
    """Btrfs needs no assembly: mounting any member (`ro`, plus `degraded` if one is gone) opens the
    whole filesystem. The volume returned is that first member, flagged with every disk involved."""
    first = members[0]
    return [Volume(id=os.path.basename(first), path=first, kind=VolumeKind.PARTITION, size=_dev_size(ctx, first),
                   readonly=True, fs_type="btrfs", from_stack=stack.id,
                   disk_ids=sorted({x.disk_id for x in stack.members}))]


# -- stop ---------------------------------------------------------------------------------

def _stack_md_names(ctx: Context, stack: Stack) -> tuple[list[str], list[str]]:
    """md arrays and containers on the stack's members or on its overlays."""
    wanted = {os.path.basename(m.device) for m in stack.members}
    wanted |= {o.kname for o in overlay.owned(ctx, OVERLAY_PREFIX, [m.device for m in stack.members]) if o.kname}
    arrays, containers = [], []
    for n in block_names(ctx.paths.sys):
        if n.startswith("md") and wanted & set(slaves_of(ctx.paths.sys, n)):
            (containers if is_md_container(ctx.paths.sys, n) else arrays).append(n)
    return arrays, containers


def stop(ctx: Context, stack: Stack) -> None:
    """Stop a started stack (arrays, activated VGs, unlocked devices, imported pools) and
    remove its overlays. Refuses while any of its devices is mounted."""
    busy = mounted_devices(ctx)
    k = stack.kind
    if k in (StackKind.MD, StackKind.IMSM, StackKind.DDF):
        arrays, containers = _stack_md_names(ctx, stack)
        if busy & set(arrays):
            raise _fail(ctx, stack, "still mounted: " + ", ".join(sorted(busy & set(arrays))))
        for n in arrays + containers:
            cp = _run(ctx, ["mdadm", "--stop", os.path.join(ctx.paths.dev, n)], env={"MDADM_NO_UDEV": "1"}, timeout=60)
            if cp.returncode != 0:
                raise _fail(ctx, stack, f"could not stop {n}: {_why(cp)}")
        _drop_overlays(ctx, stack)
    elif k == StackKind.LVM:
        if stack.name:
            ovl = [o.path for o in overlay.owned(ctx, OVERLAY_PREFIX, [m.device for m in stack.members])]
            devs = ["--devices", ",".join(ovl)] if ovl else []
            cp = _run(ctx, ["lvm", "vgchange", "-an", *devs, *vg_select(stack), "--config", lvm_config(stack.name)])
            if cp.returncode != 0:
                raise _fail(ctx, stack, f"could not deactivate '{stack.name}': {_why(cp)}")
        _drop_overlays(ctx, stack)
    elif k in (StackKind.LUKS, StackKind.BITLOCKER):
        cp = _run(ctx, ["cryptsetup", "close", crypt_name(stack)])
        if cp.returncode not in (0, 4):  # 4: no such device (already closed)
            raise _fail(ctx, stack, f"could not close it: {_why(cp)}")
    elif k == StackKind.ZFS:
        name = stack.name or stack.id.split(":", 1)[-1]
        cp = _run(ctx, ["zpool", "export", name])
        if cp.returncode != 0:
            raise _fail(ctx, stack, f"could not export the pool: {_why(cp)}")
    ctx.reporter.emit("assemble stop", f"id={stack.id}")
    guard.reapply(ctx)
