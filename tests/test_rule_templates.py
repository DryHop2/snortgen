from snortsmith_rulegen._rule_templates import _build_rule


def test_build_rule_minimal():
    r = _build_rule(
        proto="tcp", src_ip="any", src_port="any",
        dst_ip="$HOME_NET", dst_port="80",
        msg="Test", content=None, sid=1001, rev=1
    )
    assert r.startswith("alert tcp any any -> $HOME_NET 80 (")
    assert 'msg:"Test"' in r
    assert "sid:1001" in r and "rev:1" in r
    assert r.endswith(";)")


def test_build_rule_with_content_and_nocase():
    r = _build_rule(
        proto="tcp", src_ip="any", src_port="any",
        dst_ip="$HOME_NET", dst_port="80",
        msg="X", content="cmd.exe", sid=10, rev=2,
        nocase=True, offset=0, depth=100
    )
    assert 'content:"cmd.exe"' in r
    assert 'nocase' in r
    assert 'offset:0' in r and 'depth:100' in r