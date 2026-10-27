"""Disk health from `smartctl --json -a` (read-only: smartctl only reads logs and attributes).

Status rules (documented so the list screen can say why):

  FAIL  SMART overall health says FAILED; or a NVMe critical warning other than
        "temperature"; or NVMe spare below its threshold; or wear >= 100 %;
        or 100+ reallocated or pending sectors.
  WARN  any reallocated, pending or offline-uncorrectable sector; NVMe media
        errors; ATA error log or self-test log with errors; wear >= 90 %;
        temperature >= 70 C (NVMe: critical warning "temperature").
  OK    SMART readable and none of the above.
  UNKNOWN  smartctl missing, or the device gives no SMART data (many hardware
        RAID virtual disks, some USB bridges).
A single reading cannot show that a count is growing; the list screen shows the
numbers so the user can read them twice.
"""

from __future__ import annotations

import json

from ..context import Context
from .model import Disk, Health, HealthStatus, Transport

BIG = 100  # reallocated or pending sectors that count as failing


def _attempts(disk: Disk) -> list[list[str]]:
    if disk.transport == Transport.USB:
        return [["-d", "sat"], ["-d", "sat,12"], []]
    return [[]]


def _has_data(j: dict) -> bool:
    return any(k in j for k in ("smart_status", "nvme_smart_health_information_log", "ata_smart_attributes"))


def _attr_raw(j: dict, ident: int) -> int | None:
    for a in j.get("ata_smart_attributes", {}).get("table", []):
        if a.get("id") == ident:
            raw = a.get("raw", {})
            v = raw.get("value")
            if isinstance(v, int):
                return v
    return None


def parse(disk_id: str, j: dict) -> Health:
    """smartctl JSON -> Health (pure; the status rules above)."""
    nvme = j.get("nvme_smart_health_information_log") or {}
    hours = (j.get("power_on_time") or {}).get("hours")
    temp = (j.get("temperature") or {}).get("current")
    realloc = pending = wear = None
    reasons_fail: list[str] = []
    reasons_warn: list[str] = []

    passed = (j.get("smart_status") or {}).get("passed")
    if passed is False:
        reasons_fail.append("the drive reports that SMART failed")

    if nvme:
        wear = nvme.get("percentage_used")
        crit = nvme.get("critical_warning") or 0
        if crit & ~0x02:
            reasons_fail.append("the drive reports a critical warning")
        if crit & 0x02:
            reasons_warn.append("the drive is over its temperature limit")
        if nvme.get("media_errors"):
            reasons_warn.append(f"{nvme['media_errors']} media errors")
        spare, thr = nvme.get("available_spare"), nvme.get("available_spare_threshold")
        if isinstance(spare, int) and isinstance(thr, int) and spare < thr:
            reasons_fail.append("spare area is below the drive's threshold")
        if isinstance(wear, int):
            if wear >= 100:
                reasons_fail.append("the drive is worn out (100% used)")
            elif wear >= 90:
                reasons_warn.append(f"{wear}% of the drive's life used")
        hours = nvme.get("power_on_hours", hours)
        temp = nvme.get("temperature", temp)
    else:
        realloc = _attr_raw(j, 5)
        pending = _attr_raw(j, 197)
        unc = _attr_raw(j, 198)
        for label, v in (("reallocated", realloc), ("pending", pending)):
            if v and v >= BIG:
                reasons_fail.append(f"{v} {label} sectors")
            elif v:
                reasons_warn.append(f"{v} {label} sectors")
        if unc:
            reasons_warn.append(f"{unc} sectors that could not be corrected")
        if (j.get("ata_smart_error_log", {}).get("summary", {}).get("count") or 0) > 0:
            reasons_warn.append("the drive's error log has entries")
        st = j.get("ata_smart_self_test_log", {}).get("standard", {})
        if st.get("table") and any(not (t.get("status") or {}).get("passed", True) for t in st["table"][:5]):
            reasons_warn.append("a recent self-test failed")
        wl = None
        for a in j.get("ata_smart_attributes", {}).get("table", []):
            if a.get("id") in (177, 231, 233):  # wear levelling / SSD life left (normalised value)
                wl = a.get("value")
        if isinstance(wl, int) and 0 < wl <= 10 and j.get("rotation_rate") == 0:
            reasons_warn.append("the SSD is near the end of its life")

    if isinstance(temp, int) and temp >= 70:
        reasons_warn.append(f"it is hot ({temp} C)")

    if not _has_data(j):
        status, summary = HealthStatus.UNKNOWN, "No SMART data from this device."
    elif reasons_fail:
        status, summary = HealthStatus.FAIL, "Failing: " + "; ".join(reasons_fail + reasons_warn) + "."
    elif reasons_warn:
        status, summary = HealthStatus.WARN, "Warning: " + "; ".join(reasons_warn) + "."
    else:
        status, summary = HealthStatus.OK, "SMART looks healthy."
    return Health(disk_id=disk_id, status=status, summary=summary,
                  power_on_hours=hours if isinstance(hours, int) else None,
                  reallocated=realloc, pending=pending,
                  wear_percent=wear if isinstance(wear, int) else None,
                  temperature_c=temp if isinstance(temp, int) else None, raw=j)


def read(ctx: Context, disk: Disk) -> Health:
    """Ask smartctl (never runs a self-test) and emit `health ...`."""
    j: dict = {}
    missing = False
    for extra in _attempts(disk):
        cp = ctx.system.runner.run(["smartctl", "--json", "-a", *extra, disk.path], timeout=60)
        if cp.returncode == 127:
            missing = True
            break
        try:
            cand = json.loads(cp.stdout or "{}")
        except ValueError:
            continue
        if isinstance(cand, dict) and _has_data(cand):
            j = cand
            break
    h = parse(disk.id, j)
    if missing:
        h.summary = "smartctl is not available."
    fmt = lambda v: "-" if v is None else str(v)  # noqa: E731
    ctx.reporter.emit("health", f"id={disk.id}", f"status={h.status.value}", f"hours={fmt(h.power_on_hours)}",
                      f"realloc={fmt(h.reallocated)}", f"pending={fmt(h.pending)}", f"wear={fmt(h.wear_percent)}")
    return h
