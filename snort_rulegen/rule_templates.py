def build_rule(proto, src_ip, src_port, dst_ip, dst_port, msg, content, sid, rev=1):
    return(
        f'alert {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} '
        f'(msg:"{msg}"; content:"{content}"; sid:{sid}; rev:{rev};)'
    )