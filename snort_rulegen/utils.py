import ipaddress
import argparse
import re


def validate_ip(value: str) -> str:
    """Validate IP address or allow 'any' and Snort-style vars like $HOME_NET."""
    if value.lower() == "any" or value.startswith("$"):
        return value
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}")
    

def validate_port(value: str) -> str:
    """Validate port number or allow 'any'."""
    if value.lower() == "any":
        return "any"
    try:
        port = int(value)
        if 0 <= port <= 65535:
            return str(port)
        raise argparse.ArgumentTypeError("Port must be between 0 and 65535.")
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid port: must be an integer or 'any'.")
    

def validate_priority(value: str) -> str:
    """Validate Snort priority (1 - 2,147,483,647)."""
    try:
        priority = int(value)
        if 1 <= priority <= 2_147_483_647:
            return str(priority)
        raise argparse.ArgumentTypeError("Priority must be between 1 and 2,147,483,647.")
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid priority: must be an integer.")
    

def validate_offset_depth(offset: str | None, depth: str | None) -> tuple[int | None, int | None]:
    """Validate and return offset and depth as integers if valid. Raise ValueError otherwise."""
    offset_val = int(offset) if offset and offset.isdigit() else None
    depth_val = int(depth) if depth and depth.isdigit() else None

    if offset_val is not None and depth_val is not None and offset_val > depth_val:
        raise ValueError("Offset cannot be greater than depth.")
    
    return offset_val, depth_val


def validate_flags(flags: str) -> str:
    """
    Validate TCP flags for Snort rules.
    Allows flag character, modifiers, and separators:
    F, S, R, P, A, U, C, E, 0, *, +, !, ,
    """
    allowed_chars = set("FSRPAUCE0*+!,")
    if all(c in allowed_chars for c in flags):
        return flags.upper()
    raise argparse.ArgumentTypeError(f"Invalid character in TCP flags: {flags}")


def validate_pcre(pcre: str) -> str:
    """Validate basic structure of a PCRE string for Snort."""
    if not (pcre.startswith("/") and "/" in pcre[1:]):
        raise argparse.ArgumentTypeError("Invalid PCRE format. Must start with and have closing '/'.")
    return pcre


def validate_metadata(data: str) -> str:
    """Validate metadata is using key value pairs and comma delimiter."""
    parts = [item.strip() for item in data.split(",") if item.strip()]

    for part in parts:
        if " " not in part:
            raise argparse.ArgumentTypeError(
                f"Invalid metadata segment '{part}'. Each entry should be a key-value pair like 'key value'."
            )
        key, val = part.split(" ", 1)
        if not key.isidentifier():
            raise argparse.ArgumentTypeError(
                f"Invalid metadata key '{key}'. Keys should be alphanumeric and start with a letter."
            )
        if not val:
            raise argparse.ArgumentTypeError(
                f"Missing value for metadata key '{key}'."
            )
        
    return data


def validate_msg(value: str) -> str:
    """Check that reserved characters in message are properly escaped."""
    reserved = {
        ";": r"\;",
        "\\": r"\\",
        "\"": r"\"",
        "|": r"\|",
        "'": r"\;"
    }

    def escape_char(match):
        """Escape reserved characters if not escaped already"""
        char = match.group(0)
        return reserved[char]
    
    pattern = r'(?<!\\)([;\\\"|\'])'
    escaped = re.sub(pattern, escape_char, value)

    return escaped