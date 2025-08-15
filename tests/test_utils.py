import pytest
from snortsmith_rulegen._utils import (
    _validate_protocol,
    _validate_ip,
    _validate_port,
    _validate_priority,
    _validate_flags,
    _validate_pcre,
    _validate_metadata,
    _validate_msg,
    _validate_reference,
    _get_latest_revision,
    _resolve
)


def test_validate_protocol_ok():
    assert _validate_protocol("tcp") == "tcp"
    assert _validate_protocol("udp") == "udp"


def test_validate_protocol_bad():
    with pytest.raises(ValueError):
        _validate_protocol("ftp")


@pytest.mark.parametrize("val,expected", [
    ("any", "any"),
    ("$HOME_NET", "$HOME_NET"),
    ("192.168.1.1", "192.168.1.1"),
])
def test_validate_ip_ok(val, expected):
    assert _validate_ip(val) == expected


def test_validate_ip__bad():
    with pytest.raises(ValueError):
        _validate_ip("999.999.1.1")


@pytest.mark.parametrize("val,expected", [
    ("any", "any"),
    ("0", "0"),
    ("65535", "65535"),
])
def test_validate_port_ok(val, expected):
    assert _validate_port(val) == expected


def test_validate_port_bad():
    with pytest.raises(ValueError):
        _validate_port("700000")


def test_validate_priority_ok():
    assert _validate_priority("3") == "3"


def test_validate_priority_bad():
    with pytest.raises(ValueError):
        _validate_priority("abc")


def test_validate_flags_ok():
    assert _validate_flags("S, A")  == "S,A"
    assert _validate_flags(" * sa ") == "*SA"


def test_validate_flags_bad():
    with pytest.raises(ValueError):
        _validate_flags("Z")


def test_validate_pcre_ok():
    assert _validate_pcre("/user=.*root/i") == "/user=.*root/i"


def test_validate_pcre_bad():
    with pytest.raises(ValueError):
        _validate_pcre("user.*root")


def test_validate_metadata_ok():
    s = "os linux, author admin, team sec-eng"
    assert _validate_metadata(s) == s


def test_validate_metadata_bad():
    with pytest.raises(ValueError):
        _validate_metadata("os@ linux")


def test_validate_msg_escapes():
    out = _validate_msg('hello; "x" | y \\ z \' test')
    assert r'\;' in out and r'\"' in out and r'\|' in out and r'\\' in out and r"\'" in out


def test_validate_reference_ok():
    assert _validate_reference("url,https://x") == "url,https://x"


def test_validate_reference_bad():
    with pytest.raises(ValueError):
        _validate_reference("justscheme")


def test_get_latest_revision(tmp_path):
    f = tmp_path / "rules.rules"
    f.write_text('alert tcp any any -> any 80 (msg:"a"; sid:100; rev:1;)\n')
    # next should be 2
    assert _get_latest_revision(str(f), 100) == 2
    # unknown sid starts at 1
    assert _get_latest_revision(str(f), 200) == 1


def test_resolve_prefers_arg_over_config():
    config = {"default_outfile": "rules/a.rules"}
    assert _resolve("cli.rules", config, "default_outfile", "rules/local.rules") == "cli.rules"


def test_resolve_uses_config_then_fallback():
    config = {"default_outfile": "rules/a.rules"}
    assert _resolve(None, config, "default_outfile", "rules/local.rules") == "rules/a.rules"
    assert _resolve(None, {}, "default_outfile", "rules/local.rules") == "rules/local.rules"