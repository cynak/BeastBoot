"""bb-dev vm: boot a dev image in QEMU (BIOS, UEFI, Secure Boot).

The QEMU command line comes from bbdev/qemu.py, the same builder the e2e
suite uses, so a VM here behaves like the VM a failing e2e test booted.

State per image lives in out/vm/<image stem>/:
  <mode>.vars          UEFI variables (uefi and sb persist; sb-fresh and
                       sb-enrolled are rebuilt on every run)
  serial-<mode>.log    everything the guest wrote to serial port 0 (always)
  ovmf-debug.log       --fw-debug: firmware debug log (isa-debugcon 0x402);
                       seabios-debug.log in BIOS mode
  monitor.sock         QEMU human monitor (e.g. `sendkey ret`, `system_reset`)
  qmp.sock             QMP
  qemu.pid             while QEMU runs
  qemu-<mode>.cmd      the last command line, shell-quoted

Before booting, the image is checked against dist/ and the installer
(--refresh auto, the default): an image from another build gets
`bin/beast-boot update --image` (data partition kept), an image of an older
layout is rebuilt from its recipe after a question (--yes). --snapshot never
changes the image; a dist/ older than grub/ or build/ is only reported unless
--build runs `make build` first.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import diskimg, freshness, menufiles, paths, qemu
from ..msg import Failure, confirm, kv, note, rel, run_guarded, warn
from ..userconfig import UserConfig

CMD = "vm"
MODES = ("bios", "uefi", "sb", "sb-enrolled", "sb-fresh")
FIRMWARE = {"bios": "bios", "uefi": "uefi", "sb": "uefi-sb", "sb-enrolled": "uefi-sb", "sb-fresh": "uefi-sb"}
DISPLAYS = ("gtk", "sdl", "vnc", "none")
SERIALS = ("stdio", "pty", "file")
DEFAULT_MEM = 2048
DEFAULT_SMP = 2
REFRESH = ("auto", "always", "never")

# Owner GUID of the MokList entry sb-enrolled pre-seeds. Any GUID works (shim
# only looks at the certificate); this one marks entries made by bb-dev.
MOK_OWNER_GUID = "a5a1b0c3-7e57-4bee-b007-de0000000001"
ENROLL_CERT_ESP = "/ENROLL_THIS_KEY_IN_MOKMANAGER.cer"

MODE_HELP = """\
modes:
  bios         SeaBIOS (legacy BIOS boot: MBR boot.img -> core.img)
  uefi         OVMF without Secure Boot; vars persist per image
  sb           Secure Boot (Microsoft keys); vars persist per image, so a key
               enrolled by hand in MokManager stays enrolled across runs
  sb-fresh     Secure Boot with brand-new Microsoft-keys vars on every run
               (never enrolled: shim refuses GRUB and offers MokManager)
  sb-enrolled  Secure Boot with keys/beast-boot.cer pre-enrolled in MokList
               (virt-fw-vars --add-mok), rebuilt on every run

freshness (--refresh auto): an image from another dist/ build gets `bin/beast-boot
update --image` (keeps ISOs and config.cfg); an image of an older layout is
rebuilt from out/dev/<name>.bbdev.json after a question (--yes skips it);
--snapshot only warns. --refresh always updates even a current image (drops
menu-sync edits); --refresh never only warns.

state: out/vm/<image stem>/ holds <mode>.vars, serial-<mode>.log (always
written), ovmf-debug.log (--fw-debug), monitor.sock and qmp.sock.

examples:
  bb-dev vm                                  UEFI, in a window (GTK, else SDL) when available
  bb-dev vm --mode sb-enrolled --snapshot    Secure Boot, image left unchanged
  bb-dev vm --mode bios --display none       BIOS on this terminal (needs bb_serial=1)
  bb-dev vm --gdb --wait-gdb                 paused, gdb stub on :1234 (bb-dev gdb)
  bb-dev vm --print-cmd -- -d int            show the QEMU command (+ extra args)
"""


def register(sub) -> None:
    p = sub.add_parser(
        "vm", help="boot an image in QEMU (BIOS / UEFI / Secure Boot)",
        description="Boot a beast-boot image in QEMU with the same flags as the e2e tests.",
        epilog=MODE_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--image", type=Path, metavar="PATH", help=f"drive image (default: {rel(paths.DEFAULT_IMAGE)})")
    p.add_argument("--mode", choices=MODES, default="uefi", help="firmware (default: uefi)")
    p.add_argument("--bus", choices=qemu.BUSES, default="usb", help="how the drive is attached (default: usb)")
    p.add_argument("--display", choices=DISPLAYS,
                   help="gtk or sdl window, VNC server or none (default: gtk when a graphical session "
                        "and QEMU's GTK module work, else sdl, else none)")
    p.add_argument("--serial", choices=SERIALS, default="stdio",
                   help="serial port 0: this terminal (Ctrl-A x quits), a new pty, or the log file only "
                        "(default: stdio; serial-<mode>.log is written in every case)")
    p.add_argument("--snapshot", action="store_true",
                   help="write guest disk changes to a throwaway overlay (UEFI vars still persist)")
    p.add_argument("--gdb", nargs="?", type=int, const=qemu.DEFAULT_GDB_PORT, metavar="PORT",
                   help=f"gdb stub on 127.0.0.1:PORT (default {qemu.DEFAULT_GDB_PORT})")
    p.add_argument("--wait-gdb", action="store_true", help="start paused until gdb continues (implies --gdb)")
    p.add_argument("--fw-debug", action="store_true", help="firmware debug log (isa-debugcon 0x402) to ovmf-debug.log (seabios-debug.log "
                        "with --mode bios); a RELEASE OVMF, like Ubuntu's, writes nothing there")
    p.add_argument("--mem", type=int, default=DEFAULT_MEM, metavar="MB", help=f"guest memory (default {DEFAULT_MEM})")
    p.add_argument("--cdrom", type=Path, metavar="ISO", help="also attach an ISO as a CD-ROM (boots after the drive)")
    p.add_argument("--reset-vars", action="store_true", help="recreate this mode's UEFI variables first")
    p.add_argument("--print-cmd", action="store_true", help="print the QEMU command and exit")
    p.add_argument("--refresh", choices=REFRESH, default="auto",
                   help="bring the image's boot files up to date with dist/ first: auto (when they are "
                        "older), always, never (only warn) (default: auto)")
    p.add_argument("--build", action="store_true", help="run `make build` first when dist/ is older than its sources")
    p.add_argument("--yes", "-y", action="store_true",
                   help="rebuild an image of an older layout without asking")
    p.add_argument("qemu_args", nargs="*", metavar="-- QEMU_ARG", help="extra QEMU arguments, after --")
    p.set_defaults(func=run)


# ---------------------------------------------------------------------------
# Planning (pure apart from reading a few files)
# ---------------------------------------------------------------------------

@dataclass
class Host:
    qemu: str | None
    kvm: bool
    gtk_ok: bool
    gtk_reason: str
    firmware: qemu.Firmware
    data_dirs: list[Path]
    sdl_ok: bool = False

    @classmethod
    def detect(cls, env: dict) -> Host:
        q = qemu.find_qemu(env)
        ok, reason = qemu.gtk_status(q, env)
        fw = qemu.Firmware.from_env(env)
        sdl_ok, _ = qemu.sdl_status(q, env)
        return cls(q, qemu.kvm_usable(), ok, reason, fw, qemu.data_dirs(paths.REPO, fw.seabios_dir), sdl_ok)


@dataclass
class Plan:
    mode: str
    image: Path
    state: Path
    spec: qemu.QemuSpec
    vars_file: Path | None
    serial_log: Path
    fw_log: Path | None
    display: str  # gtk | sdl | vnc | none
    vnc: str | None = None
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def argv(self) -> list[str]:
        return self.spec.argv()


def socket_path(state: Path, name: str) -> Path:
    """state/<name>, or a short per-image path when that is too long for a unix socket."""
    p = state / name
    if len(str(p)) <= qemu.MAX_UNIX_PATH - 8:
        return p
    digest = hashlib.sha256(str(state).encode()).hexdigest()[:12]
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()) / f"bb-dev-{digest}"
    return base / name


def fw_log_name(mode: str) -> str:
    return "seabios-debug.log" if mode == "bios" else "ovmf-debug.log"


def build_plan(args, host: Host, *, vnc_display: int | None = None) -> Plan:
    mode = args.mode
    firmware = FIRMWARE[mode]
    image = Path(args.image or paths.DEFAULT_IMAGE).absolute()
    state = diskimg.state_dir(image)
    warnings: list[str] = []
    notes: list[str] = []

    extra = list(args.qemu_args or [])
    if extra and extra[0] == "--":
        extra = extra[1:]
    if extra and not extra[0].startswith("-"):
        raise Failure(f"unexpected argument {extra[0]!r}", "extra QEMU arguments go after --, e.g. `bb-dev vm -- -d int`")

    # Display: gtk when possible, else an SDL window, else VNC (asked for gtk) or none (default).
    want = args.display
    if want is None:
        display = "gtk" if host.gtk_ok else ("sdl" if host.sdl_ok else "none")
        if not host.gtk_ok and qemu.gui_session():
            notes.append(f"no GTK window ({host.gtk_reason}); using {'an SDL window' if host.sdl_ok else 'no window'}")
    elif want == "gtk" and not host.gtk_ok:
        fallback = "sdl" if host.sdl_ok else "vnc"
        warnings.append(f"--display gtk is not available ({host.gtk_reason}); "
                        f"using {'an SDL window' if fallback == 'sdl' else 'VNC'} instead")
        display = fallback
    else:
        display = want
    vnc = None
    if display == "vnc":
        n = qemu.free_vnc_display() if vnc_display is None else vnc_display
        vnc = f"127.0.0.1:{qemu.VNC_BASE_PORT + n}"
        display_arg = f"vnc=127.0.0.1:{n}"
    else:
        display_arg = display

    serial_log = state / f"serial-{mode}.log"
    if args.serial == "stdio":
        serial = qemu.Serial("stdio", logfile=serial_log, mux=True)
    elif args.serial == "pty":
        serial = qemu.Serial("pty", logfile=serial_log)
    else:
        serial = qemu.Serial("file", path=serial_log)

    vars_file = None if firmware == "bios" else state / f"{mode}.vars"
    fw_log = state / fw_log_name(mode) if args.fw_debug else None

    gdb_port = args.gdb
    if args.wait_gdb and gdb_port is None:
        gdb_port = qemu.DEFAULT_GDB_PORT
    if gdb_port is not None and not (1 <= gdb_port <= 65535):
        raise Failure(f"--gdb port must be 1-65535, not {gdb_port}")

    if args.mem < 128:
        raise Failure(f"--mem {args.mem}: give the guest at least 128 MB")
    cdrom = None
    if args.cdrom:
        cdrom = Path(args.cdrom).absolute()
        if not cdrom.is_file():
            raise Failure(f"--cdrom: {args.cdrom} not found")

    spec = qemu.QemuSpec(
        qemu=host.qemu or "qemu-system-x86_64",
        name=f"bb-dev {image.stem} {mode}",
        firmware=firmware,
        files=host.firmware,
        vars_file=vars_file,
        disk=image,
        bus=args.bus,
        memory=args.mem,
        smp=DEFAULT_SMP,
        kvm=host.kvm,
        data_dirs=host.data_dirs,
        snapshot=args.snapshot,
        cdrom=cdrom,
        display=display_arg,
        monitor=socket_path(state, "monitor.sock"),
        qmp=socket_path(state, "qmp.sock"),
        serial=serial,
        no_reboot=False,  # MokManager enrollment ends with a reboot
        fw_debug_log=fw_log,
        gdb_port=gdb_port,
        wait_gdb=args.wait_gdb,
        pidfile=state / "qemu.pid",
        extra=extra,
    )
    return Plan(mode, image, state, spec, vars_file, serial_log, fw_log, display, vnc, notes, warnings)


# ---------------------------------------------------------------------------
# Side effects: vars, checks, launching
# ---------------------------------------------------------------------------

def enroll_cert() -> Path:
    for c in (paths.KEYS / "beast-boot.cer", paths.DIST / "esp" / "ENROLL_THIS_KEY_IN_MOKMANAGER.cer"):
        if c.is_file():
            return c
    raise Failure("no beast-boot certificate to enroll (keys/beast-boot.cer)", "run `make keys && make build`")


def enrolled_template(host: Host, cert: Path, env: dict) -> Path:
    """MS-keys vars with `cert` in MokList, cached by content (virt-fw-vars takes ~1 s)."""
    ms = host.firmware.ovmf_vars_ms
    h = hashlib.sha256(ms.read_bytes() + cert.read_bytes() + MOK_OWNER_GUID.encode()).hexdigest()[:16]
    cache = paths.VM_OUT / ".cache" / f"ms-mok-{h}.vars"
    if not cache.is_file():
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".tmp")
        qemu.make_vars("ms+mok", tmp, firmware=host.firmware, mok_certs=[cert], owner_guid=MOK_OWNER_GUID, env=env)
        os.replace(tmp, cache)
    return cache


def prepare_vars(plan: Plan, host: Host, env: dict, reset: bool) -> str:
    """Create this mode's vars file; returns a one-line description."""
    vf = plan.vars_file
    if vf is None:
        return ""
    mode = plan.mode
    if mode == "uefi" or mode == "sb":
        kind = "plain" if mode == "uefi" else "ms"
        what = "OVMF_VARS_4M.fd" if mode == "uefi" else "OVMF_VARS_4M.ms.fd (Microsoft keys)"
        if vf.is_file() and not reset:
            return f"persistent (from {what}; --reset-vars starts over)"
        qemu.make_vars(kind, vf, firmware=host.firmware)
        return f"{'re' if reset else ''}created from {what}, persistent"
    if mode == "sb-fresh":
        qemu.make_vars("ms", vf, firmware=host.firmware)
        return "fresh OVMF_VARS_4M.ms.fd (Microsoft keys, nothing enrolled)"
    cert = enroll_cert()
    shutil.copyfile(enrolled_template(host, cert, env), vf)
    return f"fresh Microsoft keys + {rel(cert)} in MokList"


def check_image_cert(plan: Plan) -> None:
    """sb-enrolled: warn when the image's GRUB was signed with another key."""
    try:
        cert = enroll_cert()
        info = diskimg.image_info(plan.image)
        on_image = info.esp().read(ENROLL_CERT_ESP)
    except Failure:
        return
    if on_image is not None and on_image != cert.read_bytes():
        plan.warnings.append(f"the image's {ENROLL_CERT_ESP.lstrip('/')} differs from {rel(cert)}: shim will "
                             "refuse its GRUB (rebuild the image: `bb-dev image --force`)")


def _serial_on(data: bytes | None) -> bool:
    return UserConfig((data or b"").decode(errors="replace")).get("bb_serial") == "1"


def user_config_bytes(info: diskimg.ImageInfo) -> tuple[bytes | None, str]:
    """(/beast-booter/config.cfg or None if absent, "") or (None, why it could
    not be read). exFAT/NTFS need a short read-only udisks mount."""
    try:
        if info.data_fs == "fat32":
            return info.data_fat().read(diskimg.USER_CONFIG), ""
        if not diskimg.udisks_status()[0]:
            return None, diskimg.udisks_status()[1]
        with diskimg.data_access(info, readonly=True) as data:
            return data.read(diskimg.USER_CONFIG), ""
    except (Failure, OSError) as e:
        return None, str(e)


def check_bios_serial(plan: Plan) -> None:
    """BIOS: GRUB only uses the serial port with bb_serial=1, from the ESP's
    /grub/beast/device.cfg (installer --serial-console) or the data
    partition's /beast-booter/config.cfg (bb-dev debug-config)."""
    try:
        info = diskimg.image_info(plan.image)
        if _serial_on(info.esp().read("/grub/beast/device.cfg")):
            return
    except Failure:
        return
    cfg, unread = user_config_bytes(info)
    if not unread and _serial_on(cfg):
        return
    where = "on the display only" if plan.display != "none" else "nowhere you can see (--display none)"
    fix = "`bb-dev debug-config --set bb_serial=1` turns it on"
    if unread:
        msg = (f"BIOS: bb_serial is not set in device.cfg, and {diskimg.USER_CONFIG} on the {info.data_fs} "
               f"data partition could not be read ({unread}); unless it sets bb_serial=1, after SeaBIOS the "
               f"menu is {where}; {fix}")
    else:
        msg = (f"BIOS: bb_serial is not set (device.cfg or {diskimg.USER_CONFIG}), so after SeaBIOS the menu "
               f"is {where}; {fix}")
    (plan.warnings if plan.display == "none" else plan.notes).append(msg)


def check_host_mounts(plan: Plan) -> None:
    """The image must not be attached as a loop device on the host while the
    guest writes to it: two writers corrupt the data filesystem."""
    atts = diskimg.attachments(plan.image)
    if not atts:
        return
    desc = ", ".join(a.describe() for a in atts)
    if plan.spec.snapshot:
        plan.warnings.append(f"{rel(plan.image)} is attached on this host: {desc}; --snapshot keeps the image "
                             "unchanged, but the guest may see a filesystem the host is still writing")
    elif any(not a.read_only for a in atts):
        raise Failure(f"{rel(plan.image)} is attached read-write on this host: {desc}; booting it now can "
                      "corrupt its data partition", diskimg.release_hint(atts) + " (or add --snapshot)")
    else:
        plan.warnings.append(f"{rel(plan.image)} is attached read-only on this host: {desc}; it will not see "
                             f"what the guest writes ({diskimg.release_hint(atts)})")


def check_dist_fresh(args, env: dict) -> None:
    """dist/ older than grub/ or build/: warn, or `make build` with --build."""
    st = menufiles.dist_state()
    if st.present and not st.stale:
        return
    if args.build:
        from .image import make_build
        if st.present:
            note(CMD, f"dist/ is older than its sources: {st.describe()}")
        note(CMD, "running `make build` (--build) ...")
        make_build(env)
        return
    if not st.present:
        warn(CMD, "dist/ is not built, so the image's boot files cannot be checked: run `make build` (or add --build)")
    else:
        warn(CMD, f"dist/ is older than its sources ({st.describe()}); images get these old boot files: run "
                  "`make build` (or add --build); `bb-dev menu-sync` pushes just grub/ edits")


def freshen(args, plan: Plan, env: dict) -> None:
    """--refresh: make the image's boot files those of dist/ before booting it."""
    check_dist_fresh(args, env)
    img = plan.image
    v = freshness.check(img)
    if v.action == freshness.CURRENT and args.refresh == "always":
        v = freshness.Verdict(freshness.UPDATE, f"--refresh always ({v.reason})", v.state, v.dist_build)
    if v.action == freshness.CURRENT:
        plan.notes.append(f"boot files current: {v.reason}")
        return
    if v.action == freshness.UNKNOWN:
        if v.dist_build:
            warn(CMD, f"cannot tell whether {rel(img)} has the current boot files: {v.reason}")
        return
    if plan.spec.snapshot:
        warn(CMD, f"{rel(img)} has outdated boot files ({v.reason}); --snapshot leaves the image unchanged, "
                  "so this boots the old bootloader (run without --snapshot to refresh it)")
        return
    if args.refresh == "never":
        warn(CMD, f"{rel(img)} has outdated boot files ({v.reason}); --refresh never: booting it as it is")
        return
    if v.action == freshness.UPDATE:
        note(CMD, f"{rel(img)}: {v.reason}; refreshing its boot files: bin/beast-boot update --image "
                  f"{rel(img)} --yes (ISOs and config.cfg on the data partition are kept)")
        after = freshness.run_update(img, env)
        note(CMD, f"updated {rel(img)}: {after.reason}")
        plan.notes.append(f"boot files updated: {after.reason}")
        return
    recipe = freshness.read_recipe(img)
    how = (f"from its recipe {rel(freshness.recipe_path(img))}" if recipe else
           "with the `bb-dev setup` defaults (--fixtures --debug), as it has no recipe")
    note(CMD, f"{rel(img)}: {v.reason}, which `beast-boot update` cannot change; it has to be rebuilt {how}: "
              f"{freshness.rebuild_command(img)}")
    if not (args.yes or confirm(f"bb-dev vm: rebuild {rel(img)} now? Its data partition is recreated "
                                "(files and config.cfg changes made since it was built are lost)")):
        warn(CMD, "not rebuilt: booting the outdated image (--yes rebuilds without asking; "
                  "--refresh never silences this)")
        return
    freshness.ensure_modifiable(img)
    from .image import rebuild
    rebuild(img, recipe)
    sys.stdout.flush()   # the image summary before QEMU's output
    after = freshness.check(img)
    plan.notes.append(f"image rebuilt: {after.reason}")


def summary(plan: Plan, vars_desc: str, host: Host) -> None:
    s = plan.spec
    print(f"bb-dev vm: {plan.mode} ({s.firmware}), bus={qemu.normalise_bus(s.bus)}, display={plan.display}, "
          f"serial={s.serial.backend}, {'KVM' if s.kvm else 'TCG (no KVM: slow)'}, {s.memory} MB",
          file=sys.stderr)
    kv("image", rel(plan.image) + ("  (snapshot: changes are discarded)" if s.snapshot else ""))
    if plan.vars_file:
        kv("vars", f"{rel(plan.vars_file)}  {vars_desc}")
    kv("serial", rel(plan.serial_log) + ("" if s.serial.backend == "file" else f"  (copy of {s.serial.backend})"))
    if plan.fw_log:
        kv("fw log", rel(plan.fw_log))
    kv("monitor", f"{rel(s.monitor)}  (HMP: sendkey ret, system_reset, quit)")
    kv("qmp", rel(s.qmp))
    if plan.vnc:
        kv("vnc", f"{plan.vnc}  (e.g. vncviewer {plan.vnc.rsplit(':', 1)[0]}:{int(plan.vnc.rsplit(':', 1)[1]) - qemu.VNC_BASE_PORT})")
    if s.gdb_port is not None:
        kv("gdb", f"target remote :{s.gdb_port}  (or bb-dev gdb --port {s.gdb_port})"
           + ("; QEMU waits for gdb to `continue`" if s.wait_gdb else ""))
    if s.cdrom:
        kv("cdrom", rel(s.cdrom))
    if s.serial.backend == "stdio":
        kv("keys", "this terminal is serial port 0; Ctrl-A x quits QEMU, Ctrl-A h lists more")
    for n in plan.notes:
        kv("note", n)


def _nonempty(p: Path) -> bool:
    try:
        return p.stat().st_size > 0
    except OSError:
        return False


def run(args) -> int:
    return run_guarded(CMD, _run, args)


def _run(args) -> int:
    env = diskimg.tool_env()
    host = Host.detect(env)
    plan = build_plan(args, host)

    if args.print_cmd:
        for w in plan.warnings:
            warn(CMD, w)
        if not host.qemu:
            warn(CMD, "qemu-system-x86_64 not found (run `bb-dev setup`); printing the command anyway")
        if not plan.image.is_file():
            warn(CMD, f"image not found: {rel(plan.image)} (bb-dev image --fixtures --debug)")
        print(shlex.join(plan.argv()))
        return 0

    if not host.qemu:
        raise Failure("qemu-system-x86_64 not found", "run `bb-dev setup` (or scripts/bootstrap-tools.sh)")
    if not plan.image.is_file():
        raise Failure(f"image not found: {rel(plan.image)}", "build one with `bb-dev image --fixtures --debug`")
    missing = host.firmware.missing(plan.spec.firmware, qemu.default_vars_kind(plan.spec.firmware))
    if missing:
        raise Failure("firmware missing: " + ", ".join(map(str, missing)), "run `bb-dev doctor`")
    pid = diskimg.running_vm(plan.image)
    if pid:
        raise Failure(f"a VM is already running on {rel(plan.image)} (pid {pid})",
                      f"quit it first (monitor: {rel(plan.spec.monitor)}, command `quit`)")
    freshen(args, plan, env)
    check_host_mounts(plan)
    if plan.spec.gdb_port is not None and not qemu.port_free(plan.spec.gdb_port):
        raise Failure(f"port {plan.spec.gdb_port} is in use", "pick another one: --gdb PORT")

    paths.vm_state_dir(plan.image)
    for sock in (plan.spec.monitor, plan.spec.qmp):
        Path(sock).parent.mkdir(parents=True, exist_ok=True)
    if plan.mode == "sb-enrolled":
        check_image_cert(plan)
    if plan.mode == "bios":
        check_bios_serial(plan)
    vars_desc = prepare_vars(plan, host, env, args.reset_vars)
    if args.reset_vars and plan.vars_file is None:
        plan.notes.append("--reset-vars: BIOS mode has no UEFI variables")
    if plan.fw_log and plan.fw_log.exists():
        plan.fw_log.unlink()

    argv = plan.argv()
    (plan.state / f"qemu-{plan.mode}.cmd").write_text(shlex.join(argv) + "\n")
    for w in plan.warnings:
        warn(CMD, w)
    summary(plan, vars_desc, host)

    started = time.monotonic()
    proc = subprocess.Popen(argv, env=env)
    old_term = signal.signal(signal.SIGTERM, lambda *_: proc.terminate())
    interrupts = 0
    try:
        while True:
            try:
                rc = proc.wait()
                break
            except KeyboardInterrupt:
                interrupts += 1
                proc.terminate() if interrupts == 1 else proc.kill()
    finally:
        signal.signal(signal.SIGTERM, old_term)
        if proc.poll() is None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    elapsed = time.monotonic() - started
    if plan.fw_log and plan.mode != "bios" and not _nonempty(plan.fw_log):
        note(CMD, f"{plan.fw_log.name} is empty: the OVMF in {host.firmware.ovmf_dir} is a RELEASE build, which "
                  "writes nothing to the debug port (Ubuntu's is); point BB_OVMF_DIR at a DEBUG build of OVMF "
                  "(OVMF_CODE_4M*.fd + OVMF_VARS_4M*.fd) to get a log. SeaBIOS (--mode bios) always logs.")
    tail = f"serial log {rel(plan.serial_log)}"
    if plan.fw_log:
        tail += f", firmware log {rel(plan.fw_log)}"
    note(CMD, f"QEMU exited with code {rc} after {elapsed:.0f}s; {tail}")
    if rc in (0, -signal.SIGTERM, -signal.SIGINT):
        return 0
    return 128 - rc if rc < 0 else rc
