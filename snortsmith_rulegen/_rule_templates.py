def _build_rule(
    proto: str, 
    src_ip: str, 
    src_port: str, 
    dst_ip: str, 
    dst_port: str, 
    msg: str, 
    content: str | None, 
    sid: int, 
    rev: int = 1, 
    nocase: bool = False, 
    offset: int | None = None, 
    depth: int | None = None,
    flags: str | None = None, 
    pcre: str | None = None, 
    classtype: str | None = None,
    priority: int | None = None, 
    metadata: str | None = None, 
    reference: str | None = None
) -> str:
    """
    Constructs a complete Snort rule string from individual parameters.

    Args:
        proto (str): Protocol (e.g., tcp, udp, icmp, ip).
        src_ip (str): Source IP address or alias (e.g., any, $HOME_NET).
        src_port (str): Source port or alias.
        dst_ip (str): Destination IP address or alias.
        dst_port (str): Destination port or alias.
        msg (str): Rule message.
        content (str | None): Payload pattern to match.
        sid (int): Snort rule ID (SID).
        rev (int): Revision number for the rule (default: 1).
        nocase (bool): Case-insensitive content match (default: False).
        offset (int | None): Byte offset to begin match.
        depth (int | None): Byte depth to limit match.
        flags (str | None): TCP flags to match (e.g., S, SA).
        pcre (str | None): Perl-compatible regex pattern.
        classtype (str | None): Classification type.
        priority (int | None): Priority value for alerting.
        metatdata (str | None): Metadata key-value pairs.
        reference (str | None): External reference link or ID.

    Returns:
        str: A fully constructed Snort rule.
    """
    
    options = [
        f'msg:"{msg}"',
    ]

    # Add content related options
    if content:
        options.append(f'content:"{content}"')
        if nocase:
            options.append("nocase")
        if offset is not None:
            options.append(f"offset:{offset}")
        if depth is not None:
            options.append(f"depth:{depth}")

    # Optional fields
    if flags:
        options.append(f"flags:{flags}")
    if pcre:
        options.append(f'pcre:"{pcre}"')
    if classtype:
        options.append(f"classtype:{classtype}")
    if priority is not None:
        options.append(f"priority:{priority}")
    if metadata:
        options.append(f"metadata:{metadata}")
    if reference:
        options.append(f"reference:{reference}")

    # SID and revision (mandatory)
    options.append(f"sid:{sid}")
    options.append(f"rev:{rev}")

    # Final rule assembly
    rule = f'alert {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} ({"; ".join(options)};)'
    return rule