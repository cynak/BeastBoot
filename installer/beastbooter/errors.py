"""Exceptions for expected failures (printed as one line, no traceback)."""

from __future__ import annotations


class BeastError(Exception):
    """An expected failure: bad input, unsafe target, missing tool, ...

    The CLI prints the message and exits non-zero without a traceback.

    `code` is the short id the CLI puts into the progress file's "error" event
    (interfaces.py). None means "derive it from the step that was running"
    (commands.STEP_ERROR_CODES); a raise site sets it when it knows better.
    """

    code: str | None = None

    def __init__(self, *args, code: str | None = None):
        super().__init__(*args)
        if code is not None:
            self.code = code


class Cancelled(BeastError):
    """The user asked the CLI to stop (--cancel-file appeared)."""

    code = "cancelled"
