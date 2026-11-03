"""Security: under Secure Boot a plan on the (untrusted) stick only runs after
the user confirms it on the console (beastnet.script= with beastnet.sb=1).

Whoever had the stick could otherwise run downloads, disk images or MOK
requests unattended on the owner's next boot.
"""

import dataclasses
import json
import os
import subprocess
import sys

import pytest

from beastnet.script import run_script
from test_script import DATA, ISO, PKG, SHA, context, make_root, oneshot, write_plan


class Asker:
    def __init__(self, answer):
        self.answer = answer
        self.texts = []

    def __call__(self, text):
        self.texts.append(text)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _download_plan(root, https, site):
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), sha256=SHA, dest="/downloads/evil\x1b[2J\rname.iso",
               then="reboot", on_error="reboot")


@pytest.mark.parametrize("answer", ["n", "no", "q", EOFError(), OSError("no tty")])
def test_sb_plan_not_confirmed_runs_nothing(tmp_path, https, site, certs, answer):
    root = make_root(tmp_path)
    _download_plan(root, https, site)
    ctx, rep, notes = context(tmp_path, root, certs)
    ask = Asker(answer)
    outcome, result = run_script(ctx, "/plan.json", ask=ask)
    assert (outcome, result) == ("refused", None)
    assert site.requests == [] and oneshot(root) is None
    assert not (root / "mnt/data/downloads").exists() or not os.listdir(root / "mnt/data/downloads")
    assert notes == []  # on_error=reboot from the plan is not followed
    assert any(ln.startswith("BEASTNET: script confirm ") for ln in rep.lines)
    assert rep.lines[-1].startswith("BEASTNET: error script ")
    # the summary names the step and its target, without control characters
    (text,) = ask.texts
    assert "download" in text and https.url("/x.iso") in text and "evil" in text
    assert "\x1b" not in text and "\r" not in text


@pytest.mark.parametrize("answer", ["", "y", "Y", " yes "])
def test_sb_plan_confirmed_runs(tmp_path, https, site, certs, answer):
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), sha256=SHA, then="reboot")
    ctx, rep, _ = context(tmp_path, root, certs)
    outcome, result = run_script(ctx, "/plan.json", ask=Asker(answer))
    assert outcome == "done" and result.verified
    assert oneshot(root) == "/downloads/x.iso"


def test_no_sb_asks_nothing(tmp_path, https, site, certs):
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), sha256=SHA, then="reboot")
    ctx, rep, _ = context(tmp_path, root, certs)
    ctx.params = dataclasses.replace(ctx.params, sb=False)
    ask = Asker(AssertionError("must not ask without Secure Boot"))
    outcome, _ = run_script(ctx, "/plan.json", ask=ask)
    assert outcome == "done" and ask.texts == []
    assert not any("script confirm" in ln for ln in rep.lines)


def test_sb_disk_and_trust_plans_are_summarized(tmp_path, certs):
    root = make_root(tmp_path)
    ctx, rep, notes = context(tmp_path, root, certs)
    write_plan(root, action="disk", then="poweroff", on_error="poweroff", steps=[
        {"op": "scan"},
        {"op": "image", "source": "disk:nvme0\x07", "dest": "/images/a.img"},
        {"op": "restore", "image": "/images/a.img", "target": "disk:sda", "confirm": "sda"}])
    ask = Asker("n")
    assert run_script(ctx, "/plan.json", ask=ask) == ("refused", None)
    text = ask.texts[0]
    assert "image" in text and "disk:nvme0" in text and "/images/a.img" in text
    assert "restore" in text and "disk:sda" in text and "\x07" not in text
    assert "poweroff" in text and notes == []
    write_plan(root, action="trust-ubuntu", password="1234abcd", then="poweroff")
    ask = Asker("nope")
    assert run_script(ctx, "/plan.json", ask=ask) == ("refused", None)
    assert "trust-ubuntu" in ask.texts[0] and "1234abcd" not in ask.texts[0]


def test_sb_host_run_without_tty_refuses(tmp_path, https, site, certs):
    """python3 -m beastnet with sb=1 and no TTY on stdin: the plan is refused."""
    root = make_root(tmp_path)
    site.add("/x.iso", ISO)
    write_plan(root, url=https.url("/x.iso"), sha256=SHA, then="reboot")
    cp = subprocess.run([sys.executable, "-m", "beastnet", "--root", str(root), "--script", "/plan.json",
                         "--ca-file", certs.ca, "--kernel-log", os.path.join(DATA, "dmesg_mixed.txt")],
                        capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=PKG), timeout=60,
                        stdin=subprocess.DEVNULL)
    assert cp.returncode != 0
    assert "BEASTNET: script confirm " in cp.stdout
    assert "BEASTNET: error script " in cp.stdout
    assert site.requests == [] and oneshot(root) is None
    assert json.loads((root / "mnt/data/plan.json").read_text())["then"] == "reboot"
