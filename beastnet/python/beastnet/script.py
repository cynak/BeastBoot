"""Script mode (``beastnet.script=/path``): run a JSON plan without questions.

Plan (BEASTNET.md section 5)::

    {"network": {"type": "ethernet"},
     "url": "https://example.org/x.iso", "sha256": "<hex or null>", "sha256_url": null,
     "dest": "/downloads/x.iso", "then": "reboot"}

``network`` may be ``{"type": "wifi", "ssid": "...", "psk": "..."}``; both
types take an optional ``"iface"``. ``then`` is reboot (write the one-shot
entry and reboot), poweroff or stay (continue interactively).
Extensions (proposed): ``"on_error"`` (stay, reboot, poweroff or shell;
default stay) and ``"overwrite"`` (replace an existing different file).

For automated tests, a plan can run "Trust Ubuntu's Secure Boot key" instead
of a download (no network)::

    {"action": "trust-ubuntu", "step": "next", "password": "1234abcd", "then": "poweroff"}

``step`` is next (the one request the two-step rule allows now) or delete.
The password sits in plain text on the stick: use this for tests only.

Disk tools run as ``{"action": "disk", "steps": [...], "then": "poweroff"}``
(docs/DISK_TOOLS.md section 6; steps checked by disks.session.parse_steps).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import grubenv, trust
from .checksums import normalize_sha256
from .context import Context
from .download import DownloadRequest, DownloadResult
from .errors import SCRIPT, BeastNetError
from .paths import DOWNLOADS, normalize_data_path

THEN = ("reboot", "poweroff", "stay")
ON_ERROR = ("stay", "reboot", "poweroff", "shell")


TRUST_STEPS = ("next", "delete")


@dataclass
class ScriptPlan:
    network: dict
    request: DownloadRequest | None  # None for an action plan
    then: str = "stay"
    on_error: str = "stay"
    action: str | None = None  # "trust-ubuntu" | "disk"
    password: str = ""
    step: str = "next"
    steps: list = field(default_factory=list)  # "disk": the Disk tools steps


def _bad(text: str) -> BeastNetError:
    return BeastNetError(SCRIPT, text)


def parse_plan(data: object) -> ScriptPlan:
    if not isinstance(data, dict):
        raise _bad("the plan must be a JSON object")
    if data.get("action") is not None:
        return _parse_action(data)
    net = data.get("network", {"type": "ethernet"})
    if not isinstance(net, dict) or net.get("type") not in ("ethernet", "wifi"):
        raise _bad('network.type must be "ethernet" or "wifi"')
    if net["type"] == "wifi" and not (isinstance(net.get("ssid"), str) and net["ssid"]):
        raise _bad("network.ssid is required for wifi")
    for key in ("psk", "iface"):
        if net.get(key) is not None and not isinstance(net.get(key), str):
            raise _bad(f"network.{key} must be a string")
    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        raise _bad("url is required")
    for key in ("sha256", "sha256_url", "dest"):
        if data.get(key) is not None and not isinstance(data[key], str):
            raise _bad(f"{key} must be a string or null")
    try:
        sha = normalize_sha256(data.get("sha256"))
    except ValueError as e:
        raise _bad(f"sha256: {e}") from None
    dest = data.get("dest") or None
    if dest:
        try:
            dest = normalize_data_path(dest, under=DOWNLOADS)
        except ValueError:
            raise _bad(f"dest must be a file under {DOWNLOADS}/") from None
        if dest == DOWNLOADS:
            raise _bad(f"dest must be a file under {DOWNLOADS}/")
    then, on_error = _then(data)
    overwrite = data.get("overwrite", False)
    if not isinstance(overwrite, bool):
        raise _bad("overwrite must be true or false")
    req = DownloadRequest(url=url.strip(), sha256=sha, sha256_url=data.get("sha256_url") or None,
                          dest=dest, overwrite=overwrite)
    return ScriptPlan(net, req, then, on_error)


def _then(data: dict) -> tuple[str, str]:
    then = data.get("then", "stay")
    if then not in THEN:
        raise _bad(f"then must be one of {', '.join(THEN)}")
    on_error = data.get("on_error", "stay")
    if on_error not in ON_ERROR:
        raise _bad(f"on_error must be one of {', '.join(ON_ERROR)}")
    return then, on_error


def _parse_action(data: dict) -> ScriptPlan:
    if data["action"] == "disk":
        from .disks.session import parse_steps
        steps = parse_steps(data.get("steps"))
        then, on_error = _then(data)
        return ScriptPlan({}, None, then, on_error, action="disk", steps=steps)
    if data["action"] != "trust-ubuntu":
        raise _bad('action must be "trust-ubuntu" or "disk"')
    step = data.get("step", "next")
    if step not in TRUST_STEPS:
        raise _bad(f"step must be one of {', '.join(TRUST_STEPS)}")
    password = data.get("password")
    if not isinstance(password, str):
        raise _bad("password is required for trust-ubuntu")
    problem = trust.check_password(password, password)
    if problem:
        raise _bad(f"password: {problem}")
    then, on_error = _then(data)
    return ScriptPlan({}, None, then, on_error, action="trust-ubuntu", password=password, step=step)


def load_plan(data_root: str, script_path: str) -> ScriptPlan:
    """Read the plan from ``script_path`` on the data partition."""
    try:
        rel = normalize_data_path(script_path)
    except ValueError as e:
        raise _bad(str(e)) from None
    local = os.path.join(data_root, rel.lstrip("/"))
    try:
        with open(local, encoding="utf-8") as f:
            text = f.read(1024 * 1024 + 1)
    except OSError as e:
        raise _bad(f"cannot read {rel} on the data partition: {e.strerror}") from None
    if len(text) > 1024 * 1024:
        raise _bad(f"{rel} is larger than 1 MiB")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise _bad(f"{rel} is not valid JSON: {e}") from None
    return parse_plan(data)


def run_script(ctx: Context, script_path: str) -> tuple[str, DownloadResult | None]:
    """Run the plan. Returns (outcome, result): outcome "stay" means: go on
    interactively (with the result, if any); "done" means the then/on_error
    action ran (only returns in a dry run); "shell" means: exit to the shell."""
    rep = ctx.reporter
    on_error = "stay"
    try:
        plan = load_plan(ctx.paths.data, script_path)
        on_error = plan.on_error
        if plan.action == "trust-ubuntu":
            _run_trust(ctx, plan)
            return _finish(ctx, plan.then), None
        if plan.action == "disk":
            from .disks.session import run_plan
            run_plan(ctx, plan.steps)
            return _finish(ctx, plan.then), None
        assert plan.request is not None
        if ctx.net is not None:
            ctx.net.probe()
            if plan.network["type"] == "ethernet":
                ctx.net.connect_ethernet(plan.network.get("iface"))
            else:
                ctx.net.connect_wifi(plan.network.get("iface"), plan.network["ssid"],
                                     plan.network.get("psk") or "")
        try:
            result = ctx.downloader().download(plan.request)
        except ValueError as e:
            raise _bad(str(e)) from None
        if plan.then == "reboot":
            grubenv.set_oneshot(ctx.paths.grubenv, result.path)
            rep.handoff(result.path)
            ctx.system.reboot()
            return "done", result
        if plan.then == "poweroff":
            ctx.system.poweroff()
            return "done", result
        return "stay", result
    except BeastNetError as e:
        rep.error(e.code, e.text)
        if on_error == "reboot":
            ctx.system.reboot()
            return "done", None
        if on_error == "poweroff":
            ctx.system.poweroff()
            return "done", None
        if on_error == "shell":
            return "shell", None
        return "stay", None


def _run_trust(ctx: Context, plan: ScriptPlan) -> None:
    tr = trust.TrustUbuntu(ctx.paths, reporter=ctx.reporter, dry_run=ctx.dry_run,
                           runner=ctx.system.runner, say=ctx.notes.append)
    st = tr.status()
    step = trust.DELETE if plan.step == "delete" else st.next_step
    if step is None:
        if st.state == trust.TRUSTED and not st.pending:
            return  # nothing left to do
        tr.plan(st, trust.CA)  # raises why not: pending request, unavailable, built in
        return
    tr.request(step, plan.password)


def _finish(ctx: Context, then: str) -> str:
    if then == "reboot":
        ctx.system.reboot()
        return "done"
    if then == "poweroff":
        ctx.system.poweroff()
        return "done"
    return "stay"
