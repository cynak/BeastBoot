"""The real-ISO oracle on synthetic serial logs (no QEMU, no network, no KVM)."""

from __future__ import annotations

import hashlib

import pytest

from bbe2e import realiso

ISO = "/x.iso"
ENTRY = {"id": "x", "family": "dracut", "recipe": "dracut-live", "success": [r"Welcome to X!", r"\blogin: *$"]}
READY = "BEAST: ready version=0.1.2 platform=efi sb=0 esp=hd0,msdos2 data=hd0,msdos1 fs=exfat\nBEAST: info menu"
BOOT = f"BEAST: boot {ISO} recipe=dracut-live"
OK = ("Welcome to X!", "localhost login: ")


def _log(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def _judge(clean: str, entry=ENTRY, mode="uefi", fs="exfat", **kw):
    o = realiso.Oracle(entry, mode, ISO, fs)
    kw.setdefault("exited", False)
    kw.setdefault("timed_out", False)
    return realiso.judge_linux(o, clean, exit_code=None, **kw)


def test_pass_only_after_boot_and_not_from_cmdline():
    assert _judge(_log(READY, BOOT, *OK)).status == "pass"
    assert _judge(_log(READY, "Welcome to X!", "login: ", BOOT)) is None
    assert _judge(_log(READY, BOOT, "[    0.0] Kernel command line: Welcome to X! login: ")) is None
    v = _judge(_log(READY, BOOT, "Welcome to X!"), timed_out=True)
    assert v.status == "timeout" and "1/2 markers" in v.reason


def test_1_ready_record_required_and_matched():
    v = _judge(_log(BOOT, *OK))
    assert v.status == "fail" and "no BEAST: ready record" in v.reason
    v = _judge(_log(BOOT), exited=True)
    assert v.status == "fail" and "no BEAST: ready record" in v.reason
    assert _judge(_log(READY, BOOT, *OK), mode="bios").reason.startswith("wrong mode")
    sb = READY.replace("sb=0", "sb=1")
    assert _judge(_log(sb, BOOT, *OK)).reason.startswith("wrong mode")
    v = _judge(_log(READY, BOOT, *OK), fs="ntfs")
    assert v.status == "fail" and "wrong data filesystem" in v.reason
    assert _judge(_log(READY.replace("platform=efi", "platform=pc"), BOOT, *OK), mode="bios").status == "pass"


def test_2_failfast_before_end_of_last_success_fails():
    v = _judge(_log(READY, BOOT, "Welcome to X!", "Entering emergency mode.", "localhost login: "))
    assert v.status == "fail" and "gave up" in v.reason
    v = _judge(_log(READY, BOOT, "Welcome to X!", "error: can't find command 'x'.", "login: "))
    assert v.status == "fail"
    v = _judge(_log(READY, BOOT, "Welcome to X!", "BEAST: error boot-failed /x.iso", "login: "))
    assert v.status == "fail" and v.reason.startswith("menu:")
    # after the last required marker it no longer matters
    assert _judge(_log(READY, BOOT, *OK, "Entering emergency mode.")).status == "pass"


def test_3_boot_records_counted():
    v = _judge(_log(READY, BOOT, "Welcome to X!", BOOT, "login: "))
    assert v.status == "fail" and "booted more than once" in v.reason
    # one record whose recipe differs from the pin: judged by the record used
    v = _judge(_log(READY, f"BEAST: boot {ISO} recipe=suse", *OK))
    assert v.status == "fail" and "recipe=suse, expected dracut-live" in v.reason


def test_4_records_and_menu_lines_are_not_markers():
    # a BEAST record that contains marker text
    assert _judge(_log(READY, BOOT, "BEAST: info Welcome to X! login: ")) is None
    for menu in ("Press enter to boot the selected OS, 'e' to edit; Welcome to X! login: ",
                 "The selected entry will be started automatically in 5s. Welcome to X! login: ",
                 "Use the ^ and v keys to select which entry is highlighted. Welcome to X! login: "):
        assert _judge(_log(READY, BOOT, menu)) is None
    assert _judge(_log(READY, BOOT, "Command line: BOOT_IMAGE=/x Welcome to X! login: ")) is None


def test_5_recipe_not_pinned_fails():
    v = _judge(_log(READY, f"BEAST: boot {ISO} recipe=loopback", *OK), entry=dict(ENTRY, recipe=None))
    assert v.status == "fail" and "recipe not pinned" in v.reason
    cat = realiso.load()
    pinned = {e["id"]: e["recipe"] for e in cat}
    assert pinned["gparted-live"] == pinned["clonezilla"] == "live-boot"


def test_failures_misc():
    v = _judge(_log(READY, f"BEAST: boot {ISO} recipe=windows", "BEAST: error unsupported-windows /x.iso", ""))
    assert v.status == "fail" and v.reason.startswith("menu: error unsupported-windows")
    v = _judge(_log(READY, BOOT, "Entering emergency mode. Exit the shell to continue."))
    assert v.status == "fail" and "emergency" in v.reason
    v = _judge(_log(READY), exited=True)
    assert v.status == "fail" and "no 'BEAST: boot' record" in v.reason


def test_6_stale_catalog_fails_unverifiable_skips():
    e = {"id": "x", "url": "https://e.org/d/x.iso", "sha256_url": "https://e.org/d/SUMS"}
    h = "a" * 64
    with pytest.raises(realiso.Stale, match="catalog stale"):
        realiso.expected(e, get=lambda url: f"{h}  other.iso\n{h.replace('a', 'b')}  more.iso\n")
    with pytest.raises(realiso.Unverifiable):
        realiso.expected({"id": "nohash-oracle-test", "url": "https://e.org/x.iso", "unverifiable": "none"})


def test_7_hard_timeout_outlasts_scaled_deadline(monkeypatch):
    monkeypatch.setenv("BB_E2E_TIMEOUT_SCALE", "4")
    t, scale = 600.0, realiso.env.t(1)
    passed = (realiso.env.t(t) + 300) / scale  # what run_case hands to VM (which scales again)
    assert realiso.env.t(passed) == realiso.env.t(t) + 300


def test_8_windows_results_in_order():
    entry = {"id": "w", "family": "windows", "recipe": "windows",
             "result": [r"^winpe-ok\s*$", r"^iso-mounted [A-Z]: .*install\.(wim|esd)", r"^setup-running\s*$"]}
    log = _log(READY, f"BEAST: boot {ISO} recipe=windows")

    def j(txt, timed_out=False):
        return realiso.judge_windows(realiso.Oracle(entry, "uefi", ISO, "exfat"), log, txt, timed_out=timed_out)

    good = "winpe-ok\r\niso-mounted E: sources\\install.wim\r\nsetup-running\r\n"
    assert j(good).status == "pass"
    assert j("setup-running\r\niso-mounted E: install.esd\r\nwinpe-ok\r\n").status != "pass"
    v = j("winpe-ok\r\niso-mounted E:\r\nsetup-running\r\n")
    assert v.status == "fail" and "1/3" in v.reason
    assert j(None, timed_out=True).status == "timeout"
    no_ready = realiso.judge_windows(realiso.Oracle(entry, "uefi", ISO, "exfat"),
                                     _log(f"BEAST: boot {ISO} recipe=windows"), good, timed_out=False)
    assert no_ready.status == "fail" and "no BEAST: ready" in no_ready.reason


def test_9_latest_results_helper():
    def row(i, st, h="h1", v="1", mode="uefi", fs="exfat"):
        return {"id": i, "mode": mode, "fs": fs, "status": st, "iso_sha256": h, "beastboot_version": v, "reason": ""}
    rows = [row("a", "fail"), row("a", "pass"), row("a", "fail", v="0"), row("b", "pass", h="old"),
            row("b", "fail", h="new"), row("a", "pass", mode="bios")]
    got = {(r["id"], r["mode"]): r["status"] for r in realiso.latest_results(rows, version="1")}
    assert got == {("a", "uefi"): "pass", ("a", "bios"): "pass", ("b", "uefi"): "fail"}
    assert realiso.latest_results([], version="1") == []


def test_10_coverage_and_fat32_limit():
    ents = {e["id"]: e for e in realiso.load()}
    for i in ("arch", "debian13-live", "alpine-standard", "fedora-netinst", "alma10-boot", "rocky10-boot",
              "gparted-live", "clonezilla", "systemrescue"):
        assert "fat32" in ents[i]["fs"], i
    for i in ("ubuntu-desktop", "fedora-netinst", "opensuse-tw-live", "debian13-live"):
        assert "ntfs" in ents[i]["fs"], i
    assert not any("fat32" in e["fs"] and e["size"] > realiso.FAT32_MAX_FILE for e in ents.values())
    assert realiso.fs_skip_reason(6 << 30, "fat32") and "4 GiB" in realiso.fs_skip_reason(6 << 30, "fat32")
    assert realiso.fs_skip_reason(6 << 30, "exfat") is None


def test_11_stage_verifies_the_copy(tmp_path):
    src = tmp_path / "a.iso"
    src.write_bytes(b"x" * 100000)
    iso = realiso.Iso({"id": "a"}, src, 100000, hashlib.sha256(src.read_bytes()).hexdigest(), "")
    out = realiso.stage(iso, tmp_path / "w" / "s.iso")
    assert out.read_bytes() == src.read_bytes()
    src.write_bytes(b"y" * 100000)  # replaced after the check
    with pytest.raises(realiso.FetchError, match="changed after"):
        realiso.stage(iso, tmp_path / "w" / "s2.iso")
    assert not (tmp_path / "w" / "s2.iso").exists()


def test_recipe_by_filesystem():
    e = dict(ENTRY, recipe_fs={"ntfs": "loopback"})
    assert _judge(_log(READY.replace("fs=exfat", "fs=ntfs"), f"BEAST: boot {ISO} recipe=loopback", *OK), entry=e, fs="ntfs").status == "pass"
    assert _judge(_log(READY, f"BEAST: boot {ISO} recipe=loopback", *OK), entry=e).status == "fail"
