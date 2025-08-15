import builtins

from snortsmith_rulegen import _sid_manager


def test_get_next_sid_uses_temp_file(tmp_path, monkeypatch):
    # Redirect SID_FILE to a tmp location
    sid_file = tmp_path / "sid_state.txt"
    monkeypatch.setattr(_sid_manager, "SID_FILE", str(sid_file))

    # first call default start
    s1 = _sid_manager._get_next_sid()
    assert s1 == _sid_manager.DEFAULT_START

    # second call increments
    s2 = _sid_manager._get_next_sid()
    assert s2 == s1 + 1