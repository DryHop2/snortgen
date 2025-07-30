import toml
from pathlib import Path

def load_config(config_path: str | None = None) -> dict:
    """
    Load Snortsmith config from provided path or from default locations:
    - ./snortsmith.config.toml
    - ~/.snortsmithrc
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
                print(f"Warning: Failed to load config from {path}: {e}")
                return {}
            
    return {}


def get_config_value(config: dict, key: str, fallback):
    return config.get(key, fallback)