from beastnet.cmdline import parse_cmdline, read_cmdline, split_cmdline

MENU = ("BOOT_IMAGE=/beast-net/vmlinuz beastnet.data=UUID=1A2B-3C4D beastnet.esp=UUID=ABCD-1234 "
        "beastnet.sb=1 beastnet.debug=1 console=tty0 console=ttyS0,115200 quiet\n")


def test_menu_command_line():
    p = parse_cmdline(MENU)
    assert p.data == "UUID=1A2B-3C4D" and p.esp == "UUID=ABCD-1234"
    assert p.sb and p.debug and p.script is None
    assert p.consoles == ["tty0", "ttyS0,115200"]
    assert p.serial_console == "ttyS0"


def test_defaults():
    p = parse_cmdline("quiet splash")
    assert p.data is None and not p.sb and not p.debug and p.serial_console is None


def test_quotes_last_wins_and_flags():
    p = parse_cmdline('beastnet.script="/my plans/plan one.json" beastnet.debug '
                      'beastnet.sb=1 beastnet.sb=0 "beastnet.ui=plain"')
    assert p.script == "/my plans/plan one.json"
    assert p.debug  # bare flag means on
    assert not p.sb  # last one wins
    assert p.ui == "plain"


def test_debug_off_values():
    for v in ("0", "no", "off", "false", ""):
        assert not parse_cmdline(f"beastnet.debug={v}").debug


def test_split_like_the_kernel():
    assert split_cmdline('a=1  b="x y"  c "d=e f" g=h"i j" -- beastnet.debug=1') == [
        ("a", "1"), ("b", "x y"), ("c", None), ("d", "e f"), ("g", 'h"i j"')]


def test_read_missing_file(tmp_path):
    assert read_cmdline(str(tmp_path / "nope")).data is None
