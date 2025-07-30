import os

SID_FILE = "sid_state.txt"
DEFAULT_START = 1000001

def get_next_sid():
    if not os.path.exists(SID_FILE):
        sid = DEFAULT_START
    else:
        with open(SID_FILE, "r") as f:
            sid = int(f.read().strip()) + 1
    
    with open(SID_FILE, "w") as f:
        f.write(str(sid))

    return sid