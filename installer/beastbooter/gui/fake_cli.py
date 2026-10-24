"""A stand-in for the beast-booter CLI that touches nothing (GUI --demo mode and tests).

It accepts the same command line the GUI builds for the real CLI
(controller.build_cli_argv) and writes a realistic sequence of progress events
to --progress-file, with short pauses, but never opens a device and never
creates an image file. Standard library only, runnable as a plain script.

It also implements --cancel-file PATH the way the GUI expects the real CLI to
(see controller.CLI_HAS_CANCEL_FILE): before each step it checks whether PATH
exists and, if so, stops with an error event of code "cancelled" (exit 130).

Extra options choose what goes wrong:
    --fake-fail-at STEP   send an error event at STEP and exit 1
    --fake-crash-at STEP  exit 3 at STEP without an error event (a crash)
    --fake-delay SECONDS  pause per step (default 0.35)

`firmware catalog|fetch|install|remove|list` (docs/BEASTNET.md section 6) are
simulated as well: fetch downloads nothing (it writes small stand-in
<id>.cpio / <id>.json files into --out, a private temporary folder of the
GUI), and install/remove/list keep the "installed packs" of each target in a
JSON state file (--fake-state, else $BEAST_BOOTER_FAKE_FW_STATE, else one in
the temp folder) instead of touching the target. Their results report the
boot partition's free space like the real CLI: $BEAST_BOOTER_FAKE_ESP_FREE
bytes (default 300 MiB) minus the installed packs. Extra options:
    --fake-fail-at STEP   error event at STEP (fetch: "download" -> checksum-mismatch)
    --fake-delay SECONDS  pause per step
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import uuid

INSTALL_DEVICE_STEPS = [
    ("verify-dist", "Checking the boot files against manifest.json", 3),
    ("check-target", "Checking that the drive is safe to erase", 6),
    ("prepare", "Unmounting the drive's volumes", 10),
    ("partition", "Writing the {layout} partition table", 16),
    ("format-data", "Creating the {fs} storage partition {label}", 30),
    ("write-esp", "Writing the boot partition (BEAST-EFI)", 45),
    ("write-esp", "Writing the boot partition (BEAST-EFI): 12 of 41 files", 60),
    ("write-esp", "Writing the boot partition (BEAST-EFI): 33 of 41 files", 75),
    ("boot-code", "Writing the BIOS boot code", 85),
    ("flush", "Flushing data to the drive", 90),
    ("rescan", "Letting the system re-read the drive", 95),
    ("verify-write", "Reading back what was written", 98),
]
UPDATE_STEPS = [
    ("verify-dist", "Checking the boot files against manifest.json", 4),
    ("check-target", "Reading the beast-booter drive", 10),
    ("prepare", "Unmounting the drive's volumes", 18),
    ("write-esp", "Replacing the boot partition (BEAST-EFI)", 40),
    ("write-esp", "Replacing the boot partition (BEAST-EFI): 30 of 41 files", 70),
    ("boot-code", "Writing the BIOS boot code", 84),
    ("flush", "Flushing data to the drive", 90),
    ("rescan", "Letting the system re-read the drive", 95),
    ("verify-write", "Reading back what was written", 98),
]
INSTALL_IMAGE_STEPS = [
    ("verify-dist", "Checking the boot files against manifest.json", 4),
    ("check-target", "Creating the image file", 8),
    ("partition", "Writing the {layout} partition table", 18),
    ("format-data", "Creating the {fs} storage partition {label}", 35),
    ("write-esp", "Writing the boot partition (BEAST-EFI)", 60),
    ("boot-code", "Writing the BIOS boot code", 85),
    ("flush", "Flushing data to the file", 93),
    ("verify-write", "Reading back what was written", 98),
]


class Progress:
    def __init__(self, path: str, delay: float):
        self.path, self.delay = path, delay

    def emit(self, **event) -> None:
        line = json.dumps({"v": 1, **event}) + "\n"
        half = len(line) // 2
        # Two writes with a pause between them, like a writer interrupted
        # mid-line: the GUI must not act on half a line.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line[:half])
            f.flush()
            time.sleep(min(self.delay / 10, 0.02))
            f.write(line[half:])
            f.flush()


def _version(dist: str) -> str:
    try:
        with open(os.path.join(dist, "manifest.json"), encoding="utf-8") as f:
            return str(json.load(f).get("version") or "unknown")
    except (OSError, ValueError):
        return "unknown"


def _info(a: argparse.Namespace, version: str) -> dict:
    layout = getattr(a, "layout", None) or "msdos"
    sectors = (a.size // 512) if getattr(a, "size", None) else 60062500
    esp_start = (sectors - 33 - 131072) // 2048 * 2048
    return {
        "layout": layout, "version": version, "install_id": str(uuid.uuid4()),
        "disk_sectors": sectors, "bios_core_lba": 34 if layout == "gpt" else 1,
        "data": {"index": 1, "start_lba": 2048, "size_lba": esp_start - 2048,
                 "fs": getattr(a, "fs", None) or "exfat", "uuid": "1A2B-3C4D",
                 "label": getattr(a, "label", None) or "BEASTBOOTER"},
        "esp": {"index": 2, "start_lba": esp_start, "size_lba": 131072},
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["firmware"]:
        return firmware_main(argv[1:])
    p = argparse.ArgumentParser(prog="fake-beast-booter")
    p.add_argument("action", choices=("install", "update"))
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--device")
    g.add_argument("--image")
    p.add_argument("--size", type=int)
    p.add_argument("--yes", action="store_true")
    p.add_argument("--progress-file", required=True)
    p.add_argument("--cancel-file")
    p.add_argument("--dist", required=True)
    p.add_argument("--layout", default="msdos")
    p.add_argument("--fs", default="exfat")
    p.add_argument("--label", default="BEASTBOOTER")
    p.add_argument("--fake-fail-at")
    p.add_argument("--fake-crash-at")
    p.add_argument("--fake-delay", type=float, default=0.35)
    a = p.parse_args(argv)
    if not a.yes:
        print("fake-beast-booter: the GUI always passes --yes", file=sys.stderr)
        return 2
    out = Progress(a.progress_file, a.fake_delay)
    # SIGTERM (and Windows' terminate) -> the same path as Ctrl+C.
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    if a.image:
        steps, target = INSTALL_IMAGE_STEPS, a.image
    else:
        steps, target = (INSTALL_DEVICE_STEPS if a.action == "install" else UPDATE_STEPS), a.device
    layout_text = {"msdos": "MBR", "gpt": "GPT"}.get(a.layout, a.layout)
    fs_text = {"exfat": "exFAT", "fat32": "FAT32", "ntfs": "NTFS"}.get(a.fs, a.fs)
    try:
        out.emit(event="start", action=a.action, target=target)
        for step, message, pct in steps:
            if a.cancel_file and os.path.exists(a.cancel_file):
                out.emit(event="error", code="cancelled", message=f"stopped on request, before step {step}")
                print("beast-booter: stopped on request", file=sys.stderr)
                return 130
            if step == a.fake_crash_at:
                print(f"Traceback (most recent call last):\n  ...\nRuntimeError: fake crash at {step}", file=sys.stderr)
                return 3
            out.emit(event="step", step=step, message=message.format(layout=layout_text, fs=fs_text, label=a.label), pct=pct)
            if step == a.fake_fail_at:
                time.sleep(a.fake_delay)
                msg = f"write failed at byte offset 31457280 of {target}: Input/output error (the drive may be faulty)"
                out.emit(event="error", code="write-failed", message=msg)
                print(f"beast-booter: error: {msg}", file=sys.stderr)
                return 1
            if a.image and step == "check-target" and a.size and a.size % (1 << 20):
                out.emit(event="warning", message="size rounded down to whole sectors")
            time.sleep(a.fake_delay)
        out.emit(event="done", ok=True, info=_info(a, _version(a.dist)))
        return 0
    except KeyboardInterrupt:
        out.emit(event="error", code="interrupted", message="interrupted")
        print("beast-booter: interrupted", file=sys.stderr)
        return 130


# ---------------------------------------------------------------------------
# firmware
# ---------------------------------------------------------------------------

ENV_FW_STATE = "BEAST_BOOTER_FAKE_FW_STATE"


def _fw_state_path(a: argparse.Namespace) -> str:
    import tempfile

    return a.fake_state or os.environ.get(ENV_FW_STATE) or os.path.join(
        tempfile.gettempdir(), f"beast-booter-fake-firmware-{os.getuid() if hasattr(os, 'getuid') else 0}.json")


def _fw_load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _fw_save(path: str, data: dict) -> None:
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(path + ".tmp", path)


FAKE_CLUSTER = 4096


def _fw_round(n: int) -> int:
    return -(-n // FAKE_CLUSTER) * FAKE_CLUSTER


def _fw_cpio_size(entry: dict) -> int:
    """About what the real pack archive of an installed.json entry takes."""
    files = entry.get("files") or []
    return sum(int(f.get("size") or 0) + 120 + len(str(f.get("path") or "")) for f in files) + 512


def _fw_result(installed: list[dict], target: str) -> dict:
    """installed.json plus the free-space fields the real CLI reports (firmware._result)."""
    base = int(os.environ.get("BEAST_BOOTER_FAKE_ESP_FREE") or 300 * 1024 * 1024)
    packs = [dict(e, cpio_size=_fw_cpio_size(e)) for e in sorted(installed, key=lambda e: e["id"])]
    json_size = len(json.dumps({"v": 1, "packs": installed}, indent=1)) + 1 if installed else 0
    used = sum(_fw_round(p["cpio_size"]) for p in packs) + _fw_round(json_size)
    return {"v": 1, "packs": packs, "target": target, "unlisted": [], "esp_free": max(0, base - used),
            "esp_cluster": FAKE_CLUSTER, "esp_label": "BEAST-EFI", "installed_json_size": json_size}


def firmware_main(argv: list[str]) -> int:
    import hashlib

    p = argparse.ArgumentParser(prog="fake-beast-booter firmware")
    p.add_argument("command", choices=("catalog", "fetch", "install", "remove", "list"))
    g = p.add_mutually_exclusive_group()
    g.add_argument("--device")
    g.add_argument("--image")
    p.add_argument("--pack", action="append", default=[])
    p.add_argument("--out")
    p.add_argument("--from", dest="from_dir")
    p.add_argument("--catalog")
    p.add_argument("--dist")
    p.add_argument("--json", action="store_true")
    p.add_argument("--progress-file")
    p.add_argument("--fake-state")
    p.add_argument("--fake-fail-at")
    p.add_argument("--fake-crash-at")  # accepted for the demo backend; ignored here
    p.add_argument("--fake-delay", type=float, default=0.2)
    a = p.parse_args(argv)
    out = Progress(a.progress_file, a.fake_delay) if a.progress_file else None

    def emit(**ev) -> None:
        if out is not None:
            out.emit(**ev)

    def step(step_id: str, message: str, pct: float) -> bool:
        """Send a step; True when this step is the one to fail at."""
        emit(event="step", step=step_id, message=message, pct=pct)
        time.sleep(a.fake_delay)
        return step_id == a.fake_fail_at

    def fail(code: str, message: str) -> int:
        emit(event="error", code=code, message=message)
        print(f"beast-booter: error: {message}", file=sys.stderr)
        return 1

    target = a.device or a.image
    try:
        if a.command == "catalog":
            path = a.catalog or os.path.join(a.dist or ".", "esp", "beast-net", "catalog.json")
            with open(path, encoding="utf-8") as f:
                print(f.read())
            return 0
        if a.command == "fetch":
            if not a.pack or not a.out or not a.catalog:
                return fail("usage", "fetch needs --pack, --out and --catalog")
            with open(a.catalog, encoding="utf-8") as f:
                cat = json.load(f)
            packs = {pk["id"]: pk for pk in cat["packs"]}
            emit(event="start", action="firmware-fetch", target=a.out)
            for n, pid in enumerate(a.pack):
                pk = packs.get(pid)
                if pk is None:
                    return fail("invalid-argument", f"no firmware pack {pid!r} in the catalog")
                files = pk["files"]
                shown = files[:: max(1, len(files) // 4)]  # a few progress lines per pack, not one per file
                for i, fe in enumerate(shown):
                    pct = 100 * (n + (i + 1) / len(shown)) / len(a.pack)
                    if step("download", f"Downloading {pid}: {fe['path']} ({files.index(fe) + 1} of {len(files)})",
                            min(99.0, pct)):
                        return fail("checksum-mismatch",
                                    f"{fe['path']}: SHA-256 mismatch (expected {fe['sha256'][:16]}..., got "
                                    "0f3c9a51d2e4b7a8...); the download was discarded")
                cpio = f"fake cpio of {pid}\n".encode()
                with open(os.path.join(a.out, f"{pid}.cpio"), "wb") as f:
                    f.write(cpio)
                entry = {"id": pid, "catalog_tag": cat["source"]["tag"], "kernel": cat.get("kernel", ""),
                         "cpio_sha256": hashlib.sha256(cpio).hexdigest(),
                         "files": [{k: fe[k] for k in ("path", "sha256", "size")} for fe in files]}
                with open(os.path.join(a.out, f"{pid}.json"), "w", encoding="utf-8") as f:
                    json.dump(entry, f)
            emit(event="done", ok=True, info={"packs": a.pack, "out": a.out})
            return 0
        if not target:
            return fail("usage", f"firmware {a.command} needs --device or --image")
        state_path = _fw_state_path(a)
        state = _fw_load(state_path)
        installed = state.get(target, [])
        emit(event="start", action=f"firmware-{a.command}", target=target)
        if a.command == "install":
            if not a.from_dir:
                return fail("usage", "install needs --from")
            entries = []
            for name in sorted(os.listdir(a.from_dir)):
                if name.endswith(".json"):
                    with open(os.path.join(a.from_dir, name), encoding="utf-8") as f:
                        entries.append(json.load(f))
            if step("check-target", f"Checking the beast-booter drive {target}", 10):
                return fail("target-refused", f"{target} is not a beast-booter drive")
            if step("verify-packs", f"Re-checking {len(entries)} pack(s) against the catalog", 30):
                return fail("verify-failed", "a file in the pack does not match the catalog")
            ids = {e["id"] for e in entries}
            if _fw_result([x for x in installed if x["id"] not in ids] + entries, target)["esp_free"] <= 0:
                return fail("no-space", f"not enough space on the boot partition (BEAST-EFI) of {target} for "
                                        f"{', '.join(sorted(ids))}; deselect packs or remove installed ones first")
            for i, e in enumerate(entries):
                if step("write-firmware", f"Writing beast-net/firmware/{e['id']}.cpio", 40 + 50 * (i + 1) / len(entries)):
                    return fail("write-failed", f"write failed on {target}: Input/output error (the drive may be faulty)")
                installed = [x for x in installed if x["id"] != e["id"]] + [e]
            state[target] = installed
            _fw_save(state_path, state)
            step("flush", "Flushing data to the drive", 97)
        elif a.command == "remove":
            if len(a.pack) != 1:
                return fail("usage", "remove takes one --pack")
            if not any(x["id"] == a.pack[0] for x in installed):
                return fail("invalid-argument", f"{a.pack[0]} is not installed on {target}")
            step("write-firmware", f"Removing beast-net/firmware/{a.pack[0]}.cpio", 60)
            installed = [x for x in installed if x["id"] != a.pack[0]]
            state[target] = installed
            _fw_save(state_path, state)
        else:
            step("check-target", f"Reading beast-net/firmware/installed.json on {target}", 50)
        result = _fw_result(installed, target)
        if a.command == "list" and a.json:
            print(json.dumps(result))
        emit(event="done", ok=True, info={"installed": result})
        return 0
    except KeyboardInterrupt:
        emit(event="error", code="cancelled", message="stopped on request")
        return 130


if __name__ == "__main__":
    sys.exit(main())
