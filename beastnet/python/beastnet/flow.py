"""The interactive flow: Network -> Link -> Download -> Done."""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from . import grubenv, trust
from .cmdline import netboot
from .context import Context, Quit, make_request
from .download import DownloadResult, Plan, human_size
from .errors import TLS, WIFI_AUTH, BeastNetError, Cancelled
from .net import HardwareReport, NetInfo
from .ui import UI, Field, Item
from .wifi import OPEN, SECURITY_LABEL, WifiNetwork, check_passphrase


def looks_like_iso(path: str) -> bool:
    """ISO 9660 volume descriptor ("CD001") at sector 16 (also in hybrid ISOs)."""
    try:
        with open(path, "rb") as f:
            f.seek(0x8001)
            return f.read(5) == b"CD001"
    except OSError:
        return False


TRUST_TITLE = "Trust Ubuntu's Secure Boot key"


class Interactive:
    def __init__(self, ctx: Context, ui: UI) -> None:
        self.ctx = ctx
        self.ui = ui
        self.netinfo: NetInfo | None = None
        self.url = "https://"
        self.checksum = ""

    def make_trust(self) -> trust.TrustUbuntu:
        return trust.TrustUbuntu(self.ctx.paths, reporter=self.ctx.reporter, dry_run=self.ctx.dry_run,
                                 runner=self.ctx.system.runner, say=self.ctx.notes.append)

    # -- top level ------------------------------------------------------------------
    def run(self, result: DownloadResult | None = None, action: str | None = None) -> None:
        if netboot(self.ctx):
            self.netboot_loop()
            return
        if action == "trust-ubuntu":
            self.trust_ubuntu(entry=True)
        elif action == "disk":
            self.disk_tools(entry=True)
        elif action == "winboot":
            self.winboot(entry=True)
        if result is not None:
            self.ui.set_step(3)
            self.done_step(result)
        while True:
            if self.netinfo is None and self.ctx.net is not None:
                self.ui.set_step(0)
                self.netinfo = self.network_step()
            self.ui.set_step(1)
            req = self.link_step()
            if req is None:
                self.more_menu()
                continue
            self.ui.set_step(2)
            result = self.download_step(req)
            if result is None:
                continue
            self.ui.set_step(3)
            self.done_step(result)

    def netboot_loop(self) -> None:
        """Started over the network (beastnet.netboot=1, BeastServer): Disk tools only.
        There is no stick to download to or to keep a boot entry on."""
        while True:
            self.disk_tools(entry=True)
            choice = self.ui.menu("beast-net", "Started over the network: Disk tools only.",
                                  [Item("Disk tools: recovery and cloning", "disks")] + self.common_items(),
                                  back=False)
            if choice and choice != "disks":
                self.common(choice)

    def common(self, action: str) -> None:
        if action == "shell":
            self.ui.shell(self.ctx.system.shell)
        elif action in ("reboot", "poweroff"):
            what = "Rebooting" if action == "reboot" else "Powering off"
            fn = self.ctx.system.reboot if action == "reboot" else self.ctx.system.poweroff
            self.ui.task(what, f"{what}..." if netboot(self.ctx) else
                         f"{what}: writing everything to the stick first...", fn)
            raise Quit(action)

    def common_items(self) -> list[Item]:
        return [Item("Open a shell", "shell", hint="Type 'exit' to come back."),
                Item("Reboot" if netboot(self.ctx) else "Reboot to the beast-boot menu", "reboot"),
                Item("Power off", "poweroff")]

    def more_menu(self) -> None:
        items = [Item("Back to the link", None)]
        if self.ctx.net is not None:
            items.append(Item("Change the network", "network"))
        items.append(Item(TRUST_TITLE, "trust", hint="Lets this computer start boot loaders and "
                          "kernels signed by Ubuntu (Canonical) with Secure Boot on (two steps, "
                          "confirmed in MokManager)."))
        items.append(Item("Disk tools: recovery and cloning", "disks",
                          hint="See disks and RAID sets, check health, clone, image or restore. "
                               "Every disk stays read-only until you confirm a copy target."))
        choice = self.ui.menu("More", "", items + self.common_items())
        if choice == "network":
            self.netinfo = None
        elif choice == "trust":
            self.trust_ubuntu()
        elif choice == "disks":
            self.disk_tools()
        elif choice:
            self.common(choice)

    def show_error(self, e: BeastNetError, title: str = "Something went wrong") -> None:
        self.ctx.reporter.error(e.code, e.text)
        text = f"{e.text}\n\n{e.hint}" if e.hint else e.text
        items = [Item("OK", "ok")]
        if e.code == TLS and "clock" in e.hint:
            items.append(Item("Set the clock", "clock"))
        if self.ui.menu(f"{title} ({e.code})", text, items, kind="error") == "clock":
            self.set_clock()

    def set_clock(self) -> None:
        error = ""
        while True:
            v = self.ui.form("Set the clock", "The current date and time in UTC (used for this "
                             "session only; the computer's clock is not changed).",
                             [Field("t", "Date and time (YYYY-MM-DD HH:MM, UTC)")], error=error)
            if v is None:
                return
            if re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d", v["t"].strip()) and \
                    self.ctx.system.set_clock(v["t"].strip()):
                return
            error = "Use the form 2026-10-23 14:05"

    # -- 1. network -----------------------------------------------------------------
    def network_step(self) -> NetInfo:
        svc = self.ctx.net
        assert svc is not None
        rep = self.ui.task("Network", "Looking for network adapters...", svc.probe)
        error: BeastNetError | None = None
        auto = True
        while True:
            if auto:
                auto = False
                if rep.ethernet:
                    try:
                        return self.ui.task("Network", "Connecting with the network cable "
                                            f"({', '.join(n.name for n in rep.ethernet)}): asking "
                                            "for an address (DHCP)...", svc.connect_ethernet)
                    except BeastNetError as e:
                        error = e
                if rep.wifi:
                    got = self.wifi_step(rep)
                    if got:
                        return got
            choice = self.network_menu(rep, error)
            error = None
            if choice == "wired":
                try:
                    return self.ui.task("Network", "Asking for an address (DHCP)...",
                                        svc.connect_ethernet)
                except BeastNetError as e:
                    self.ctx.reporter.error(e.code, e.text)
                    error = e
            elif choice == "wifi":
                got = self.wifi_step(rep)
                if got:
                    return got
            elif choice == "rescan":
                def rescan() -> HardwareReport:
                    self.ctx.system.rescan_hardware()
                    return svc.probe()
                rep = self.ui.task("Network", "Looking for network adapters again...", rescan)
                auto = True
            elif choice:
                self.common(choice)

    def network_menu(self, rep: HardwareReport, error: BeastNetError | None) -> str | None:
        text = []
        if error:
            text.append(error.text + (f" {error.hint}" if error.hint else ""))
        if not rep.nics:
            text.append("No network adapter was found. A USB network adapter works too: "
                        "plug it in and choose Rescan.")
        if rep.rfkill_hard:
            text.append("WiFi is switched off with a hardware switch or key.")
        text += [m.advice() for m in rep.missing]
        items = []
        if rep.ethernet:
            items.append(Item("Use the network cable", "wired",
                              detail=", ".join(n.name for n in rep.ethernet)))
        if rep.wifi:
            items.append(Item("Choose a WiFi network", "wifi",
                              detail=", ".join(n.name for n in rep.wifi)))
        items.append(Item("Rescan for adapters", "rescan"))
        return self.ui.menu("Network", "\n\n".join(text), items + self.common_items(),
                            kind="warn" if text else "", back=False)

    def wifi_step(self, rep: HardwareReport) -> NetInfo | None:
        svc = self.ctx.net
        assert svc is not None
        iface = rep.wifi[0].name
        if len(rep.wifi) > 1:
            iface = self.ui.menu("WiFi adapter", "Which WiFi adapter should be used?",
                                 [Item(n.name, n.name, detail=n.driver) for n in rep.wifi])
            if iface is None:
                return None
        while True:
            try:
                nets = self.ui.task("WiFi", f"Scanning for WiFi networks ({iface})...",
                                    lambda: svc.scan(iface))
            except BeastNetError as e:
                self.show_error(e, "WiFi")
                return None
            items = [self._net_item(n) for n in nets]
            items += [Item("Other network (hidden name)...", "hidden"),
                      Item("Scan again", "rescan")]
            text = (f"{len(nets)} network{'s' if len(nets) != 1 else ''} found on {iface}."
                    if nets else "No networks found. Move closer to the access point and scan again.")
            sel = self.ui.menu("Choose a WiFi network", text, items)
            if sel is None:
                return None
            if sel == "rescan":
                continue
            got = self.join_wifi(iface, None if sel == "hidden" else sel)
            if got:
                return got

    @staticmethod
    def _net_item(n: WifiNetwork) -> Item:
        detail = f"{SECURITY_LABEL.get(n.security, n.security):<6} {n.band:>7}"
        hint = ""
        if not n.supported:
            hint = f"{SECURITY_LABEL.get(n.security)} networks cannot be used by beast-net."
        elif n.security == OPEN:
            hint = "Open network: no password, traffic can be seen by others nearby."
        return Item(n.ssid, n, detail=detail, bars=n.bars, lock=n.security != OPEN,
                    hint=hint, kind="" if n.supported else "muted")

    def join_wifi(self, iface: str, network: WifiNetwork | None) -> NetInfo | None:
        svc = self.ctx.net
        assert svc is not None
        ssid: str | bytes = network.ssid_bytes if network else ""
        if network is not None and not network.supported:
            self.ui.message("WiFi", f"{network.ssid} uses {SECURITY_LABEL[network.security]}, "
                            "which beast-net cannot join. Choose another network.", kind="warn")
            return None
        if network is not None and network.security == OPEN:
            if not self.ui.confirm(
                    "Open network",
                    f"{network.ssid} has no password: others nearby can see which sites you "
                    "visit. The download itself stays protected by HTTPS and the checksum.",
                    "Join anyway", "Back", kind="warn"):
                return None
        error = ""
        while True:
            passphrase = ""
            if network is None:
                v = self.ui.form("Hidden network", "Type the network name and its passphrase "
                                 "(leave the passphrase empty for an open network).",
                                 [Field("ssid", "Network name (SSID)", ssid if isinstance(ssid, str) else ""),
                                  Field("psk", "Passphrase", secret=True)], error=error)
                if v is None:
                    return None
                ssid, passphrase = v["ssid"].strip(), v["psk"]
                if not ssid:
                    error = "Type the network name."
                    continue
            elif network.needs_passphrase:
                v = self.ui.form(f"Join {network.ssid}",
                                 f"{SECURITY_LABEL[network.security]} network. Type its passphrase.",
                                 [Field("psk", "Passphrase", secret=True,
                                        hint="Case-sensitive. F2 shows what you typed.")],
                                 error=error)
                if v is None:
                    return None
                passphrase = v["psk"]
                problem = check_passphrase(network.security, passphrase)
                if problem:
                    error = problem
                    continue
            name = network.ssid if network else str(ssid)
            try:
                return self.ui.task("WiFi", f"Connecting to {name} and asking for an address...",
                                    lambda: svc.connect_wifi(iface, ssid, passphrase, network=network,
                                                             hidden=network is None))
            except BeastNetError as e:
                self.ctx.reporter.error(e.code, e.text)
                if e.code == WIFI_AUTH and (network is None or network.needs_passphrase):
                    error = f"{e.text}. {e.hint}".strip()
                    continue
                self.show_error(e, "WiFi")
                return None

    # -- 2. link --------------------------------------------------------------------
    def link_step(self):
        error = ""
        text = ("Type or paste the link to the ISO (https://). The server's certificate is "
                "checked before anything is downloaded.\n"
                "Optional, recommended: the ISO's SHA-256, or the https:// link to its "
                "checksum file (for example SHA256SUMS). The download is then verified.")
        while True:
            v = self.ui.form("Link", text, [
                Field("url", "ISO link", self.url),
                Field("checksum", "SHA-256 or checksum file link (optional)", self.checksum),
            ], error=error)
            if v is None:
                return None
            self.url, self.checksum = v["url"].strip(), v["checksum"].strip()
            try:
                return make_request(self.url, self.checksum)
            except BeastNetError as e:
                self.ctx.reporter.error(e.code, e.text)
                error = f"{e.text}. {e.hint}".strip()
            except ValueError as e:
                error = str(e)

    # -- 3. download ----------------------------------------------------------------
    def download_step(self, req) -> DownloadResult | None:
        d = self.ctx.downloader()
        host = urlsplit(req.url).hostname or req.url
        try:
            plan: Plan = self.ui.task("Download", f"Contacting {host}...", lambda: d.prepare(req))
        except BeastNetError as e:
            self.show_error(e, "Cannot download")
            return None
        except ValueError as e:
            self.ui.message("Cannot download", str(e), kind="error")
            return None
        overwrite = False
        if plan.exists:
            if plan.expected:
                try:
                    reused = self.ui.task("Download", f"{plan.dest} is already on the stick: "
                                          "checking it against the SHA-256...",
                                          lambda: d.check_existing(plan))
                except (OSError, Cancelled):
                    reused = None
                if reused is not None:
                    return reused
            stem, ext = os.path.splitext(os.path.basename(plan.dest))
            items = [Item(f"Keep both: save the new one as {stem}-1{ext} (or the next free name)", "rename"),
                     Item("Replace the file on the stick", "replace")]
            if not plan.expected:
                items.append(Item("Use the file that is already there", "existing"))
            items.append(Item("Cancel", None))
            choice = self.ui.menu(
                "Already on the stick",
                f"{plan.dest} already exists on the stick"
                + (" and does not match the SHA-256." if plan.expected else "."), items, kind="warn")
            if choice is None:
                return None
            if choice == "existing":
                size = os.path.getsize(plan.local)
                return DownloadResult(plan.dest, plan.local, size, "", None, reused=True)
            if choice == "rename":
                plan = d.with_unique_name(plan)
            overwrite = choice == "replace"
        lines = [f"From: {plan.url}", f"To:   {plan.dest} (on the stick)"]
        if plan.total:
            lines.append(f"Size: {human_size(plan.total)}")
        if plan.expected:
            lines.append(f"Will verify SHA-256 {plan.expected[:16]}...")
        else:
            lines.append("No checksum given: the file will not be verified.")
        try:
            return self.ui.download("Downloading", lines,
                                    lambda progress, cancel: d.fetch(plan, progress, cancel,
                                                                     overwrite=overwrite))
        except Cancelled:
            self.ui.message("Download cancelled", "The partial download is kept on the stick. "
                            "Start the same link again to resume it.")
        except BeastNetError as e:
            self.show_error(e, "Download failed")
        return None

    # -- 4. done --------------------------------------------------------------------
    def done_step(self, result: DownloadResult) -> None:
        lines = [f"Saved as {result.path} ({human_size(result.size)})."]
        if result.verified:
            lines.append(f"SHA-256 verified: {result.sha256}")
        elif result.sha256:
            lines.append(f"SHA-256: {result.sha256}")
            lines.append("Not verified (no checksum given): compare it with the one the "
                         "distribution publishes.")
        if result.reused:
            lines.append("This file was already on the stick.")
        if not looks_like_iso(result.local):
            lines.append("Note: this does not look like an ISO image; the menu may not boot it.")
        items = [Item("Boot it now", "boot",
                      hint="Reboots into the beast-boot menu, which starts this ISO once. "
                           "It stays on the stick for next time."),
                 Item("Download another ISO", "another")] + self.common_items()
        while True:
            choice = self.ui.menu("Done", "\n".join(lines), items, kind="ok", back=False)
            if choice == "another":
                return
            if choice == "boot":
                self.boot(result)
            elif choice:
                self.common(choice)

    def boot(self, result: DownloadResult) -> None:
        try:
            grubenv.set_oneshot(self.ctx.paths.grubenv, result.path)
            self.ctx.reporter.handoff(result.path)
        except BeastNetError as e:
            self.ctx.reporter.error(e.code, e.text)
            if not self.ui.confirm("Cannot set up the one-time boot",
                                   f"{e.text}\n\nThe ISO is saved on the stick: reboot and pick "
                                   f"{result.path} in the menu.", "Reboot anyway", "Back",
                                   kind="error"):
                return
        self.common("reboot")

    # -- Trust Ubuntu's Secure Boot key (build/trust/README.md) ---------------------
    def disk_tools(self, entry: bool = False) -> None:
        """Disk tools (docs/DISK_TOOLS.md); ``entry`` as for trust_ubuntu."""
        from .diskflow import DiskScreens
        DiskScreens(self).run(entry)

    def winboot(self, entry: bool = False) -> None:
        from .winflow import WinbootScreens
        WinbootScreens(self).run()

    def trust_ubuntu(self, entry: bool = False) -> None:
        """The action's screens. ``entry``: opened by the boot menu entry
        (beastnet.action=trust-ubuntu) instead of from the helper's own menu."""
        old = self.ui.set_mode("beast-net: Ubuntu's Secure Boot key", ())
        try:
            self._trust_loop(self.make_trust(), entry)
        finally:
            self.ui.set_mode(*old)

    def _trust_loop(self, tr: trust.TrustUbuntu, entry: bool) -> None:
        while True:
            try:
                st = self.ui.task(TRUST_TITLE, "Reading the Secure Boot key lists (MokListRT, "
                                  "MokListXRT)...", tr.status)
            except BeastNetError as e:
                self.show_error(e, TRUST_TITLE)
                return
            items: list[Item] = []
            step = st.next_step
            if step:
                items.append(Item(trust.STEP_LABEL[step], step, hint=_STEP_HINT[step]))
            if st.can_delete:
                items.append(Item(trust.STEP_LABEL[trust.DELETE], trust.DELETE,
                                  hint="Asks MokManager to remove Canonical's CA from MokList. "
                                       "Ubuntu's revocations stay in MokListX."))
            if st.pending:
                items.append(Item("Reboot now to confirm it in MokManager", "reboot"))
            items.append(Item("What does this do?", "about"))
            items.append(Item("Download an ISO from a link", None) if entry else Item("Back", None))
            items += [it for it in self.common_items() if not (st.pending and it.value == "reboot")]
            kind = {trust.TRUSTED: "ok", trust.PARTIAL: "warn", trust.UNAVAILABLE: "warn"}.get(st.state, "")
            choice = self.ui.menu(TRUST_TITLE, trust.state_text(st), items, kind=kind, back=not entry)
            if choice is None:
                return
            if choice == "about":
                self.ui.document("What does this do?", trust.ABOUT, [Item("Back", True)])
            elif choice in (trust.REVOCATIONS, trust.CA, trust.DELETE):
                self._trust_request(tr, st, choice)
            else:
                self.common(choice)

    def _trust_request(self, tr: trust.TrustUbuntu, st: trust.Status, step: str) -> None:
        try:
            req = tr.plan(st, step)
        except BeastNetError as e:
            self.show_error(e, TRUST_TITLE)
            return
        go = self.ui.document(trust.STEP_LABEL[step], trust.request_text(req),
                              [Item("Continue", True), Item("Back", False)],
                              kind="warn" if step == trust.CA else "")
        if go is not True:
            return
        error = ""
        while True:
            v = self.ui.form("One-time password", "MokManager asks for this password once, after "
                             "the reboot, to confirm the request. Choose a new one; it is used "
                             "only for this request.",
                             [Field("pw", "One-time password", secret=True,
                                    hint="4-32 letters or digits. MokManager may use a US keyboard."),
                              Field("again", "Type it again", secret=True)], error=error)
            if v is None:
                return
            error = trust.check_password(v["pw"], v["again"])
            if not error:
                break
        try:
            req = self.ui.task(TRUST_TITLE, f"Requesting it with mokutil ({req.var})...",
                               lambda: tr.request(step, v["pw"], v["again"]))
        except BeastNetError as e:
            self.show_error(e, TRUST_TITLE)
            return
        choice = self.ui.menu("Requested: reboot to confirm", trust.next_text(req),
                              [Item("Reboot now", "reboot"), Item("Back", None)], kind="ok")
        if choice:
            self.common(choice)


_STEP_HINT = {
    trust.REVOCATIONS: "Puts the certificates Ubuntu revoked into MokListX first, so they stay "
                       "refused. Confirm it in MokManager after a reboot.",
    trust.CA: "Adds Canonical's Master CA to MokList (all revocations are in MokListX): shim "
              "then accepts boot loaders and kernels signed by Ubuntu (Canonical). Confirm it "
              "in MokManager after a reboot.",
}
