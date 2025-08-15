import sys
import importlib


def test_main_no_args_goes_interactive(monkeypatch):
    # stub functions to observe calls
    called = {"interactive": False}

    def fake_run_interactive():
        called["interactive"] = True

    # Re-import main after monkeypatching
    import snortsmith_rulegen.snortsmith as snortsmith
    monkeypatch.setattr(snortsmith, "run_interactive", fake_run_interactive)

    # Important: mack CLI argv to only contain program name
    monkeypatch.setenv("PYTHONWARNINGS", "ignore")
    monkeypatch.setattr(sys, "argv", ["snortsmith"])

    # Now import main fresh so it binds the patched function
    mod = importlib.import_module("snortsmith_rulegen.main")
    # Call main()
    mod.main()

    assert called["interactive"] is True