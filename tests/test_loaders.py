import json

from snortsmith_rulegen._loaders import (
    _as_none, 
    _parse_bool,
    _parse_int,
    _normalize_row,
    iter_rules
)


def test_as_none():
    assert _as_none("") is None
    assert _as_none("  ") is None
    assert _as_none("x") == "x"


def test_parse_bool():
    assert _parse_bool("Y") is True
    assert _parse_bool("0") is False
    assert _parse_bool("") is None
    assert _parse_bool("maybe") is None


def test_parse_int():
    assert _parse_int("5") == 5
    assert _parse_int("x") == "x"
    assert _parse_int("") is None


def test_normalize_row_types():
    row = {"nocase": "y", "sid": "100", "priority": "3", "offset": "0", "depth": "100", "msg": "hello world"}
    out = _normalize_row(row)
    assert out["nocase"] is True
    assert out["sid"] == 100 and out["priority"] == 3
    assert out["offset"] == 0 and out["depth"] == 100
    assert out["msg"] == "hello world"


def test_iter_rules_json(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps([{"msg": "a"}, {"msg": "b"}]))
    rows = list(iter_rules(str(p)))
    assert rows[0]["msg"] == "a" and rows[1]["msg"] == "b"


def test_iter_rules_csv(tmp_path):
    p = tmp_path / "b.csv"
    p.write_text("msg,nocase,priority\nhello,y,2\n")
    rows = list(iter_rules(str(p)))
    assert rows[0]["msg"] == "hello"
    assert rows[0]["nocase"] is True
    assert rows[0]["priority"] == 2