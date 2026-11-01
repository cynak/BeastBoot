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

Under Secure Boot (``beastnet.sb=1``) the plan comes from a stick anyone may
have had in their hands, so nothing runs before the user confirms a summary of
it on the console (``confirm_plan``); no answer, no terminal or anything but
Enter/y refuses it.
"""

from __future__ import annotations

import json
import os
import sys
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO

from . import grubenv, trust
from .checksums import normalize_sha256
from .context import Context
from .download import DownloadRequest, DownloadResult
from .errors import SCRIPT, BeastNetError
from .paths import DOWNLOADS, normalize_data_path

THEN = ("reboot", "poweroff", "stay")
ON_ERROR = ("stay", "reboot", "poweroff", "shell")


TRUST_STEPS = ("next", "delete")
YES = ("", "y", "yes")
# Disk step keys worth showing in the summary (what is read and what is written).
SUMMARY_KEYS = ("disk", "stack", "members", "source", "on", "image", "dest", "target", "partition")

Ask = Callable[[str], str]  # shows the text, returns the answer; EOFError/OSError: nobody there


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


def shown(value: object, limit: int = 160) -> str:
    """``value`` safe to print on a terminal: no control or format characters
    (escape sequences, carriage returns, bidi overrides), one line, shortened."""
    text = "".join(ch for ch in str(value) if unicodedata.category(ch)[0] != "C")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def plan_summary(plan: ScriptPlan) -> list[str]:
    """One line per thing the plan does (kind and target), for the confirmation."""
    if plan.action == "trust-ubuntu":
        lines = [f"trust-ubuntu step={shown(plan.step)} (asks shim to change the Secure Boot keys)"]
    elif plan.action == "disk":
        lines = []
        for s in plan.steps:
            words = [f"{k}={shown(','.join(s[k]) if isinstance(s[k], list) else s[k])}"
                     for k in SUMMARY_KEYS if k in s]
            lines.append(" ".join([shown(s["op"]), *words]))
    else:
        assert plan.request is not None
        req = plan.request
        dest = req.dest or f"{DOWNLOADS}/(name from the link)"
        lines = [f"download {shown(req.url)}", f"  to {shown(dest)}"
                 + (" (replacing an existing file)" if req.overwrite else "")]
        if plan.network.get("type") == "wifi":
            lines.insert(0, f"network wifi ssid={shown(plan.network.get('ssid', ''))}")
    return [*lines, f"then {shown(plan.then)}"]


def console_ask(text: str, inp: IO[str] | None = None, out: IO[str] | None = None) -> str:
    """Ask on the console (stdin/stdout: /init gives the app the console)."""
    inp = inp or sys.stdin
    out = out or sys.stdout
    if not inp.isatty():
        raise EOFError("no terminal to ask on")
    out.write(text)
    out.flush()
    line = inp.readline()
    if not line:
        raise EOFError("end of input")
    return line


def _drop_typeahead(inp: IO[str]) -> None:
    """Forget keys pressed before the question (an Enter while booting is no answer)."""
    try:
        import termios
    except ImportError:
        return
    try:
        termios.tcflush(inp.fileno(), termios.TCIFLUSH)
    except (termios.error, OSError, ValueError, AttributeError):
        pass


def confirm_plan(ctx: Context, plan: ScriptPlan, script_path: str, ask: Ask | None = None) -> None:
    """Show what the plan does and wait for Enter/y. Raises BeastNetError(SCRIPT)
    for any other answer, no answer or no terminal."""
    if ask is None:
        _drop_typeahead(sys.stdin)
        ask = console_ask
    body, n = [], 0
    for line in plan_summary(plan):
        if line.startswith("  "):  # continues the item above
            body.append(f"     {line.strip()}")
        else:
            n += 1
            body.append(f"  {n}. {line}")
    text = "\n".join(["", f"Secure Boot is on, and the stick asks to run the plan {shown(script_path)}:",
                      *body, "Run it? Press Enter or type y to run it; anything else cancels: "])
    # The event line comes after the type-ahead flush: tests answer when they see it.
    ctx.reporter.emit("script confirm", f"path={script_path}", f"steps={n}")
    try:
        answer = ask(text)
    except (EOFError, OSError):
        answer = None
    if answer is None or answer.strip().lower() not in YES:
        why = "no answer" if answer is None else "cancelled"
        raise _bad(f"the plan {script_path} was not run: {why} on the console (Secure Boot is on, "
                   "a plan must be confirmed)")


def run_script(ctx: Context, script_path: str,
               ask: Ask | None = None) -> tuple[str, DownloadResult | None]:
    """Run the plan. Returns (outcome, result): outcome "stay" means: go on
    interactively (with the result, if any); "done" means the then/on_error
    action ran (only returns in a dry run); "shell" means: exit to the shell;
    "refused" means: under Secure Boot the user did not confirm it (nothing
    ran, the plan's on_error is not followed). ``ask`` replaces the console
    question (tests)."""
    rep = ctx.reporter
    on_error = "stay"
    try:
        plan = load_plan(ctx.paths.data, script_path)
        if ctx.params.sb:
            try:
                confirm_plan(ctx, plan, script_path, ask)
            except BeastNetError as e:
                rep.error(e.code, e.text)
                return "refused", None
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
