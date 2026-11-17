"""Two disks that report the same serial (many USB bridges report a fixed iSerial such as
"0123456789ABCDEF" or all zeros): the serial names neither, neither can be written while
both are attached, and a look-alike that takes the planned target's place is noticed
(docs/DISK_TOOLS.md s.1 rule 3)."""

# ruff: noqa: F811  (the env fixture of test_disks_copy.py is imported and used as an argument)
import copy as pycopy

import pytest

from beastnet import errors as E
from beastnet.disks import copy as C
from beastnet.errors import BeastNetError
from test_disks_copy import env, mk  # noqa: F401  (env is a fixture)

GENERIC = "0123456789ABCDEF"


def _same_serial(env, *ids):
    for d in env.inv.disks:
        if d.id in ids:
            d.serial, d.wwn = GENERIC, ""   # USB bridges: no WWN either


@pytest.mark.parametrize("target", [GENERIC, "sdb"])
def test_a_target_with_a_shared_serial_is_refused(env, target):
    _same_serial(env, "sdb", "sde")
    with pytest.raises(BeastNetError) as ei:
        mk(env, target=target, confirm=GENERIC)
    assert ei.value.code == E.DISK_REFUSED and "two disks report the serial" in ei.value.text


def test_a_shared_serial_names_no_disk(env):
    _same_serial(env, "sda", "sde")
    assert env.inv.serial_shared(GENERIC) and not env.inv.serial_shared("TGT123456")
    assert env.inv.disk(GENERIC) is None
    assert env.inv.disk("sda").id == "sda" and env.inv.disk("sde").id == "sde"


def test_a_source_named_by_a_shared_serial_is_refused(env):
    _same_serial(env, "sda", "sde")
    with pytest.raises(BeastNetError) as ei:
        C.plan(env.ctx, env.inv, "clone", GENERIC, "TGT123456", hooks=env.hooks,
               mapfile_dir=str(env.tmp / "data" / "maps"))
    assert ei.value.code == E.DISK_REFUSED and "two disks report the serial" in ei.value.text
    # by device name it can still be read
    assert C.plan(env.ctx, env.inv, "clone", "sda", "TGT123456", hooks=env.hooks,
                  mapfile_dir=str(env.tmp / "data" / "maps")).target_disk_id == "sdb"


def test_a_look_alike_plugged_in_after_the_plan_stops_the_write(env):
    """A second disk with the target's serial appears between plan and write."""
    p = mk(env, confirm="123456")
    other = pycopy.deepcopy(env.inv)
    next(d for d in other.disks if d.id == "sde").serial = "TGT123456"
    env.rescan_inv = other
    with pytest.raises(BeastNetError) as ei:
        C._reidentify(env.ctx, p, env.hooks)
    assert ei.value.code == E.DISK_REFUSED and "nothing was written" in ei.value.text


def test_another_disk_with_the_same_serial_and_size_is_noticed(env):
    """The planned target is unplugged and another bridge with the same serial and an
    equal-size disk takes its kernel name before the copy starts."""
    _same_serial(env, "sdb")
    p = mk(env, target=GENERIC, confirm=GENERIC[-6:])
    assert p.target_fingerprint
    assert C._reidentify(env.ctx, p, env.hooks).id == "sdb"      # unchanged: accepted
    with open(env.files["sdb"], "r+b") as f:                     # the other disk's first sector
        f.write(b"another disk")
    with pytest.raises(BeastNetError) as ei:
        C._reidentify(env.ctx, p, env.hooks)
    assert ei.value.code == E.DISK_CHANGED and "nothing was written" in ei.value.text


def test_fingerprint_reads_both_ends_and_the_size(tmp_path):
    a = tmp_path / "a"
    a.write_bytes(b"\0" * (3 << 20))
    base = C._fingerprint(str(a))
    with open(a, "r+b") as f:
        f.seek((3 << 20) - 1)
        f.write(b"x")
    tail = C._fingerprint(str(a))
    a.write_bytes(b"\0" * (4 << 20))
    assert len({base, tail, C._fingerprint(str(a))}) == 3
    assert C._fingerprint(str(tmp_path / "missing")) == ""
