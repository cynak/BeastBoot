"""Following the CLI's JSON-lines --progress-file: partial lines, garbage, unknown events."""

from __future__ import annotations

import json

import pytest

from beastbooter.gui import progress as pg
from beastbooter.gui.progress import ProgressReader, ProgressState, parse_line
from beastbooter.interfaces import PROGRESS_STEPS


def line(**ev) -> bytes:
    return (json.dumps({"v": 1, **ev}, ensure_ascii=False) + "\n").encode()


@pytest.fixture
def pfile(tmp_path):
    return tmp_path / "progress.jsonl"


def append(path, data: bytes) -> None:
    with open(path, "ab") as f:
        f.write(data)


def test_missing_file_is_not_an_error(pfile):
    r = ProgressReader(pfile)
    assert r.read_new() == [] and r.finish() == []


def test_reads_only_new_complete_lines(pfile):
    r = ProgressReader(pfile)
    append(pfile, line(event="start", action="install", target="/dev/sdb"))
    evs = r.read_new()
    assert [e.kind for e in evs] == ["start"]
    assert r.read_new() == []
    append(pfile, line(event="step", step="partition", message="P", pct=20))
    assert [e.data["step"] for e in r.read_new()] == ["partition"]


def test_partial_line_waits_for_the_rest(pfile):
    r = ProgressReader(pfile)
    data = line(event="step", step="write-esp", message="Writing", pct=55)
    append(pfile, data[:17])
    assert r.read_new() == []
    append(pfile, data[17:-1])
    assert r.read_new() == []
    append(pfile, data[-1:])
    (ev,) = r.read_new()
    assert ev.kind == "step" and ev.data["pct"] == 55


def test_utf8_split_across_reads(pfile):
    r = ProgressReader(pfile)
    data = line(event="warning", message="Laufwerk wird geprüft – bitte warten")
    cut = data.index("ü".encode()) + 1  # in the middle of the two-byte sequence
    append(pfile, data[:cut])
    assert r.read_new() == []
    append(pfile, data[cut:])
    (ev,) = r.read_new()
    assert ev.data["message"] == "Laufwerk wird geprüft – bitte warten"


def test_many_lines_in_one_read_and_crlf(pfile):
    r = ProgressReader(pfile)
    append(pfile, line(event="start", action="update", target="x").replace(b"\n", b"\r\n")
           + b"\n\n" + line(event="step", step="flush", pct=90) + line(event="warning", message="w"))
    assert [e.kind for e in r.read_new()] == ["start", "step", "warning"]


def test_finish_reads_unterminated_last_line(pfile):
    r = ProgressReader(pfile)
    append(pfile, line(event="start", action="install", target="x") + b'{"v":1,"event":"done","ok":true}')
    assert [e.kind for e in r.read_new()] == ["start"]
    assert [e.kind for e in r.finish()] == ["done"]
    assert r.finish() == []


def test_truncated_file_starts_over(pfile):
    r = ProgressReader(pfile)
    append(pfile, line(event="start", action="install", target="x") * 3)
    assert len(r.read_new()) == 3
    pfile.write_bytes(line(event="warning", message="new"))
    (ev,) = r.read_new()
    assert ev.kind == "warning"


def test_overlong_line_is_dropped(pfile, monkeypatch):
    monkeypatch.setattr(pg, "MAX_LINE_BYTES", 100)
    r = ProgressReader(pfile)
    append(pfile, b"x" * 150)
    (ev,) = r.read_new()
    assert ev.kind == "invalid" and "longer than" in ev.note
    append(pfile, b"y" * 20 + b"\n" + line(event="warning", message="after"))
    assert [e.data.get("message") for e in r.read_new()] == ["after"]  # the tail of the long line is skipped


@pytest.mark.parametrize("raw, kind, note", [
    (b"not json", "invalid", "not JSON"),
    (b"[1, 2]", "invalid", "not a JSON object"),
    (b'{"v": 1}', "invalid", 'no "event"'),
    (b'{"v": 1, "event": 5}', "invalid", 'no "event"'),
    (b'{"v": 1, "event": "telemetry", "x": 1}', "unknown", "unknown event 'telemetry'"),
    (b"\xff\xfe garbage", "invalid", "not JSON"),
])
def test_parse_bad_lines(raw, kind, note):
    ev = parse_line(raw)
    assert ev.kind == kind and note in ev.note


def test_step_fields_are_normalised():
    ev = parse_line(b'{"v":1,"event":"step","step":"format-data"}')
    assert ev.data["message"] == pg.STEP_TITLES["format-data"] and ev.data["pct"] is None
    assert parse_line(b'{"v":1,"event":"step","step":"x","pct":250}').data["pct"] == 100.0
    assert parse_line(b'{"v":1,"event":"step","step":"x","pct":-3}').data["pct"] == 0.0
    assert parse_line(b'{"v":1,"event":"step","step":"x","pct":true}').data["pct"] is None
    assert parse_line(b'{"v":1,"event":"step","step":"x","pct":"50"}').data["pct"] is None
    assert parse_line(b'{"v":1,"event":"step","step":7}').data["step"] == ""


def test_error_and_done_fields():
    ev = parse_line(b'{"v":1,"event":"error","code":"unsafe-target","message":"refusing"}')
    assert (ev.data["code"], ev.data["message"]) == ("unsafe-target", "refusing")
    ev = parse_line(b'{"v":1,"event":"error"}')
    assert (ev.data["code"], ev.data["message"]) == ("error", "(no message)")
    assert parse_line(b'{"v":1,"event":"done","ok":"yes"}').data["ok"] is False  # only true is true
    assert parse_line(b'{"v":1,"event":"done","ok":true,"info":[1]}').data["info"] is None


def test_newer_schema_version_is_noted_but_used():
    ev = parse_line(b'{"v":2,"event":"warning","message":"m"}')
    assert ev.kind == "warning" and "version 2" in ev.note
    st = ProgressState()
    st.apply(ev)
    st.apply(parse_line(b'{"v":2,"event":"warning","message":"m2"}'))
    assert st.warnings == ["m", "m2"]
    assert sum("schema version" in entry.text for entry in st.log) == 1  # noted once


def test_state_folding():
    st = ProgressState()
    for raw in (
        line(event="start", action="install", target="/dev/sdb"),
        line(event="step", step="verify-dist", message="Checking", pct=3),
        line(event="step", step="partition", message="Partitioning", pct=20),
        line(event="step", step="partition", message="Partitioning again", pct=10),  # never backwards
        line(event="bogus"),
        line(event="warning", message="slow"),
    ):
        st.apply(parse_line(raw))
    assert st.started and st.action == "install" and st.target == "/dev/sdb"
    assert st.pct == 20 and st.message == "Partitioning again"
    assert st.steps_seen == ["verify-dist", "partition"] and st.wrote_to_target
    assert st.warnings == ["slow"]
    assert [e.level for e in st.log].count("debug") == 1  # the bogus event
    st.apply(parse_line(line(event="done", ok=True, info={"layout": "gpt"})))
    assert st.done_seen and st.done_ok and st.pct == 100 and st.done_info == {"layout": "gpt"}


def test_error_event_state():
    st = ProgressState()
    st.apply(parse_line(line(event="step", step="check-target", pct=5)))
    st.apply(parse_line(line(event="error", code="not-beast-booter", message="no marker")))
    assert (st.error_code, st.error_message) == ("not-beast-booter", "no marker")
    assert not st.wrote_to_target  # check-target writes nothing
    assert st.log[-1].level == "error"


def test_every_contract_step_has_a_title():
    assert set(pg.STEP_TITLES) == set(PROGRESS_STEPS)
    assert set(pg.WRITING_STEPS) <= set(PROGRESS_STEPS)
    assert "verify-dist" not in pg.WRITING_STEPS and "prepare" not in pg.WRITING_STEPS
