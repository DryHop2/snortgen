"""
sid_manager.py

Handles persistent SID (Snort Rule ID) tracking for Snortsmith.
Stores the last used SID in a file and increments it automatically.
"""

import os

SID_FILE = "sid_state.txt"
DEFAULT_START = 1000001

def get_next_sid() -> int:
    """
    Retrieves the next available SID by reading and incrementing a local file.

    If the SID file doesn't exist, starts from DEFAULT_START.
    The updated SID is written back to the file.

    Returns:
        int: The next available SID.
    """
    try:
        if not os.path.exists(SID_FILE):
            sid = DEFAULT_START
        else:
            with open(SID_FILE, "r") as f:
                sid = int(f.read().strip()) + 1
    except (ValueError, OSError) as e:
        print(f"[WARNING] SID file error: {e}. Resetting to {DEFAULT_START}.")
        sid = DEFAULT_START

    try:    
        with open(SID_FILE, "w") as f:
            f.write(str(sid))
    except OSError as e:
        print(f"[ERROR] Failed to write SID to {SID_FILE}: {e}")

    return sid