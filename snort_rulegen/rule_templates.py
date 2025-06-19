def build_rule(proto, src_ip, src_port, dst_ip, dst_port, 
               msg, content, sid, rev=1, 
               nocase=False, offset=None, depth=None,
               flags=None, pcre=None):
    
    options = [
        f'msg:"{msg}"',
    ]

    if content:
        options.append(f'content:"{content}"')
        if nocase:
            options.append("nocase")
        if offset:
            options.append(f"offset:{offset}")
        if depth:
            options.append(f"depth:{depth}")

    if flags:
        options.append(f"flags:{flags}")
    if pcre:
        options.append(f'pcre:"{pcre}"')

    options.append(f"sid:{sid}")
    options.append(f"rev:{rev}")

    rule = f'alert {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} ({"; ".join(options)};)'
    return rule