import ipaddress
import argparse


def validate_ip(val):
    """Validate IP address or allow 'any' and Snort-style vars like $HOME_NET."""
    if val.lower() == "any" or val.startswith("$"):
        return val
    try:
        ipaddress.ip_address(val)
        return val
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {val}")
    

def validate_port(val):
    """Validate port number or allow 'any'."""
    if val.lower() == "any":
        return "any"
    try:
        port = int(val)
        if 0 <= port <= 65535:
            return str(port)
        raise argparse.ArgumentTypeError("Port must be between 0 and 65535.")
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid port: must be an integer or 'any'.")
    

def validate_priority(val):
    """Validate Snort priority (1 - 3)."""
    try:
        priority = int(val)
        if priority in (1, 2, 3):
            return str(priority)
        raise argparse.ArgumentTypeError("Priority must be 1, 2, or 3.")
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid priority: must be an integer.")