def build_rule(proto, src_ip, src_port, dst_ip, dst_port, msg, content, sid, rev=1, nocase=False):
    options = [
        f'msg:"{msg}"',
    ]

    if content:
        options.append(f'content:"{content}"')
        if nocase:
            options.append("nocase")

    options.append(f"sid:{sid}")
    options.append(f"rev:{rev}")

    rule = f'alert {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} ({"; ".join(options)};)'
    return rule