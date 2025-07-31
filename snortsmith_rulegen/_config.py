import toml
from pathlib import Path
from typing import Any

def _load_config(config_path: str | None = None) -> dict[str, Any]:
    """
    Load Snortsmith configuration from a TOML file.

    Order of precedence:
    1. A specific path provided via `config_path`
    2. Default file: ./snortsmith.config.toml
    3. Fallback: ~/.snortsmithrc

    Args:
        config_path (str | None): Path to the config file or None to use defaults.

    Returns:
        dict: Parsed config as a dictionary. Includes '__source__' key for traceability.
    """

    candidates = []

    if config_path:
        candidates.append(Path(config_path))
    else:
        candidates.extend([
            Path.cwd() / "snortsmith.config.toml",
            Path.home() / ".snortsmithrc"
        ])

    for path in candidates:
        if path.exists():
            try:
                with open(path, "r") as f:
                    data = toml.load(f)
                    data["__source__"] = str(path)
                    return data
            except Exception as e:
                print(f"[WARNING] Failed to load config from {path}: {e}")
                return {}
    # No config found      
    return {}


def _get_config_value(config: dict[str, Any], key: str, fallback: Any) -> Any:
    """
    Retrieves a config value with fallback if the key is missing.

    Args:
        config (dict): Loaded config dictionary.
        key (str): Key to look up.
        fallback (Any): Fallback value if key is not found.

    Returns:
        Any: The resolved config value.
    """

    return config.get(key, fallback)