"""Errors with the machine-readable codes of docs/BEASTNET.md section 5."""

from __future__ import annotations

# Codes from the contract.
NO_NETWORK = "no-network"
WIFI_AUTH = "wifi-auth"
DHCP = "dhcp"
TLS = "tls"
HTTP = "http"
REFUSED_PLAIN_HTTP = "refused-plain-http"
CHECKSUM_MISMATCH = "checksum-mismatch"
NO_SPACE = "no-space"
MOUNT = "mount"
GRUBENV = "grubenv"
# Additions proposed to the lead (not yet in the contract table):
SCRIPT = "script"  # the beastnet.script plan is missing or invalid
EXISTS = "exists"  # destination exists and the plan did not allow replacing it
INTERNAL = "internal"  # a bug: an unexpected exception

CODES = frozenset({
    NO_NETWORK, WIFI_AUTH, DHCP, TLS, HTTP, REFUSED_PLAIN_HTTP, CHECKSUM_MISMATCH,
    NO_SPACE, MOUNT, GRUBENV, SCRIPT, EXISTS, INTERNAL,
})


class BeastNetError(Exception):
    """A failure the user (and the BEASTNET: output) should hear about.

    ``code`` is one of CODES, ``text`` a one-line explanation, ``hint`` an
    optional longer "what you can do" for the interactive screens.
    """

    def __init__(self, code: str, text: str, hint: str = "") -> None:
        if code not in CODES:
            raise ValueError(f"unknown error code {code!r}")
        super().__init__(f"{code}: {text}")
        self.code = code
        self.text = text
        self.hint = hint


class Cancelled(Exception):
    """The user cancelled a running operation."""
