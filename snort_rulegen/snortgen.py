import os
from snort_rulegen.rule_templates import build_rule
from snort_rulegen.sid_manager import get_next_sid

def run():
    print("Snort Rule Generator")
    print("--------------------")

    proto = input("Protocol [tcp/udp/icmp]: ").strip() or "tcp"
    src_ip = input("Source IP [any]: ").strip() or "any"
    src_port = input("Source Port [any]: ").strip() or "any"
    dst_ip = input("Destination IP [$HOME_NET]: ").strip() or "$HOME_NET"
    dst_port = input("Destination port [80]: ").strip() or "80"
    content = input("Content to match (e.g., cmd.exe): ").strip()
    msg = input("Rule message: ").strip()

    sid = get_next_sid()
    rule = build_rule(proto, src_ip, src_port, dst_ip, dst_port, msg, content, sid)

    print("\nGenerated Rule:")
    print(rule)

    out_path = "rules/local.rules"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "a") as f:
        f.write(rule + "\n")

    print(f"\nRule saved to {out_path}")