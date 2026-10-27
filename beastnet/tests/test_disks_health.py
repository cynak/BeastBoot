"""Disk health from (stubbed) smartctl JSON."""

import json

import pytest

from beastnet.disks import health
from beastnet.disks.model import Disk, HealthStatus, Transport
from disk_fakes import Env, cp


def mkdisk(transport=Transport.SATA):
    return Disk("sda", "/dev/sda", "M", "S", "", 1 << 30, 512, 4096, transport, False, False)


def ata(realloc=0, pending=0, unc=0, passed=True, hours=1234, temp=35, errlog=0):
    def a(i, raw):
        return {"id": i, "value": 100, "raw": {"value": raw}}
    return {"smart_status": {"passed": passed}, "power_on_time": {"hours": hours}, "temperature": {"current": temp},
            "ata_smart_attributes": {"table": [a(5, realloc), a(197, pending), a(198, unc)]},
            "ata_smart_error_log": {"summary": {"count": errlog}}}


def nvme(used=3, crit=0, media=0, spare=100, thr=10):
    return {"smart_status": {"passed": True}, "power_on_time": {"hours": 50}, "temperature": {"current": 40},
            "nvme_smart_health_information_log": {"percentage_used": used, "critical_warning": crit,
                                                  "media_errors": media, "available_spare": spare,
                                                  "available_spare_threshold": thr, "power_on_hours": 50}}


@pytest.mark.parametrize("data,status", [
    (ata(), HealthStatus.OK),
    (ata(realloc=3), HealthStatus.WARN),
    (ata(pending=1), HealthStatus.WARN),
    (ata(unc=2), HealthStatus.WARN),
    (ata(errlog=4), HealthStatus.WARN),
    (ata(realloc=500), HealthStatus.FAIL),
    (ata(pending=100), HealthStatus.FAIL),
    (ata(passed=False), HealthStatus.FAIL),
    (ata(temp=75), HealthStatus.WARN),
    (nvme(), HealthStatus.OK),
    (nvme(used=95), HealthStatus.WARN),
    (nvme(used=100), HealthStatus.FAIL),
    (nvme(media=2), HealthStatus.WARN),
    (nvme(crit=0x04), HealthStatus.FAIL),
    (nvme(crit=0x02), HealthStatus.WARN),
    (nvme(spare=5, thr=10), HealthStatus.FAIL),
    ({}, HealthStatus.UNKNOWN),
])
def test_status_rules(data, status):
    assert health.parse("sda", data).status == status


def test_numbers_and_event(tmp_path):
    e = Env(tmp_path)
    e.runner.on("smartctl", cp(4, json.dumps(ata(realloc=8, pending=2))))  # nonzero exit bits still carry JSON
    h = health.read(e.ctx, mkdisk())
    assert (h.status, h.power_on_hours, h.reallocated, h.pending) == (HealthStatus.WARN, 1234, 8, 2)
    assert e.rep.lines[-1] == "BEASTNET: health id=sda status=warn hours=1234 realloc=8 pending=2 wear=-"
    assert e.runner.calls[0] == ["smartctl", "--json", "-a", "/dev/sda"]


def test_nvme_wear_in_event(tmp_path):
    e = Env(tmp_path)
    e.runner.on("smartctl", cp(0, json.dumps(nvme(used=7))))
    h = health.read(e.ctx, mkdisk(Transport.NVME))
    assert h.wear_percent == 7 and e.rep.lines[-1].endswith("realloc=- pending=- wear=7")


def test_usb_bridge_tries_sat_first_then_auto(tmp_path):
    e = Env(tmp_path)
    e.runner.on("smartctl", lambda argv, env, inp: cp(1, "{}") if "-d" in argv else cp(0, json.dumps(ata())))
    h = health.read(e.ctx, mkdisk(Transport.USB))
    assert h.status == HealthStatus.OK
    assert ["-d", "sat"] == e.runner.calls[0][3:5] and e.runner.calls[-1] == ["smartctl", "--json", "-a", "/dev/sda"]


def test_no_smartctl(tmp_path):
    e = Env(tmp_path)
    h = health.read(e.ctx, mkdisk())
    assert h.status == HealthStatus.UNKNOWN and "not available" in h.summary
