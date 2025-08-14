import csv
import json
from pathlib import Path


_BOOL_TRUE = {"1", "true", "t", "y", "yes"}
_BOOL_FALSE = {"0", "false", "f", "n", "no"}


def _as_none(s):
    """
    Normalize 'empty' or whitespace only input to Python None.
    
    Converts None -> None, "" -> None, "   " -> None.
    All other values are return as stripped string.
    """
    if s is None:
        return None
    s = str(s).strip()
    return None if s == "" else s


def _parse_bool(s):
    """
    Convert common truthy/falsey string values to Python True/False.

    Matches are case-insensitive and checked against predefined sets:
        truthy: 1, true, t, y, yes
        falsey: 0, false, f, n, no

    Returns:
        True / False if matched,
        None if no match or value is empty.
    """
    s = _as_none(s)
    if s is None:
        return None
    ls = s.lower()
    if ls in _BOOL_TRUE:
        return True
    if ls in _BOOL_FALSE:
        return False
    # leave as None; validators/_resolve will decide
    return None


def _parse_int(s):
    """
    Convert int-like strings to int.

    If converstoin fails, the original value is returned unchanged
    so that downstream validators can raise appropriate error.
    Empty/whitspace only becomes None.
    """
    s = _as_none(s)
    if s is None:
        return None
    try:
        return int(s)
    except ValueError:
        return s # let validator raise the proper error later
    

def _normalize_row(d: dict) -> dict:
    """
    Normalize a single rule row before validation.

    - Converts empty strings to None.
    - Parses 'nocase' as a boolean (if present).
    - Parses sid/priority/offset/depth as integers (if possible).
    - Leaves all other values untouched for later validation.

    This is run on each for in a JSON/CSV batch file prior to 
    applying config fallbacks and field validators.
    """
    # Shallow copy
    r = {k: _as_none(v) for k, v in d.items()}

    # Boolean
    if "nocase" in r:
        r["nocase"] = _parse_bool(r["nocase"])

    # Int-ish fields (let validators complain on bad strings)
    for k in ("sid", "priority", "offset", "depth"):
        if k in r:
            r[k] = _parse_int(r[k])

    return r


def iter_rules(filepath: str):
    """
    Load and normalize rules from a JSON or CSV batch file.

    Detects file type by extension (.json / .csv) then yields
    each rule as a dict with basic type normalization applied via 
    _normalize_row().

    Raise:
        ValueError: if file format is unsupported or structure is invalid.
    """
    path = Path(filepath)
    ext = path.suffix.lower()

    if ext == ".json":
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            # Support {"rules": [...]} if someone does that
            data = data.get("rules", [])
        if not isinstance(data, list):
            raise ValueError("JSON batch file must be a list of rule objects (or {'rules': [...]})")
        for row in data:
            # trust existing JSON typing; still normalize empties
            yield _normalize_row(row)
        return
    
    if ext == ".csv":
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield _normalize_row(row)
        return
    
    raise ValueError(f"Unsupported batch file type: {ext}. Use .json or .csv")