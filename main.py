import argparse

from snort_rulegen.snortgen import run_interactive
from snort_rulegen.utils import (
    validate_protocol,
    validate_ip,
    validate_port,
    validate_priority,
    validate_flags,
    validate_pcre,
    validate_metadata,
    validate_msg
)


def main():
    parser = argparse.ArgumentParser(
        prog="snortgen",
        description=(
            "SnortGen: An interactive CLI tool to generate Snort rules quickly.\n\n"
            "SnortGen walks you through building a rule step-by-step. "
            "It supports common fields like protocol, IP, port, content matching, PCRE, flags, "
            "classtype, metadata, and more. SID assignment is automatic and rules are saved to "
            "'rules/local.rules' by default.\n\n"
            "Designed for security engineers, analysts, and anyone who wants to generate Snort rules "
            "without memorizing syntax."
        ),
        epilog="More info: https://github.com/DryHop2/snortgen",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive prompt mode"
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="Snortgen 1.0.0"
    )

    parser.add_argument(
        "--proto",
        type=validate_protocol,
        default="tcp",
        help="Protocol to use for the rule (default: tcp; options: tcp, udp, icmp, ip)"
    )

    parser.add_argument(
        "--src-ip",
        type=validate_ip,
        default="any",
        help="Source IP to use for the rule (default: any)"
    )

    parser.add_argument(
        "--src-port",
        type=validate_port,
        default="any",
        help="Source port to use for the rule (default: any)"
    )

    parser.add_argument(
        "--dst-ip",
        type=validate_ip,
        default="$HOME_NET",
        help="Destination IP to use for the rule (default: $HOME_NET)"
    )

    parser.add_argument(
        "--dst-port",
        type=validate_port,
        default="80",
        help="Destination port to use for the rule (default: 80)"
    )

    parser.add_argument(
        "--content",
        type=str,
        help="String or hex pattern to match in payload (e.g., 'cmd.exe' or '|90 90 90|')"
    )

    parser.add_argument(
        "--nocase",
        action="store_true",
        help="Perform case-insensitive content matching"
    )

    parser.add_argument(
        "--offset",
        type=int,
        help="What byte to begin search for payload relative to beginning of packet or buffer."
    )

    parser.add_argument(
        "--depth",
        type=int,
        help="How deep (by bytes) to look into the packet or buffer for the specified pattern"
    )

    parser.add_argument(
        "--flags",
        type=validate_flags,
        help="TCP flags to match for rule (e.g., S, SA, *SA, SF,CE)"
    )

    parser.add_argument(
        "--pcre",
        type=validate_pcre,
        help="Perl-compatible regex pattern (e.g., /user.*=root/i)"
    )

    parser.add_argument(
        "--classtype",
        type=str,
        help="Classification to indicate the type of attack suspected in the event"
    )

    parser.add_argument(
        "--priority",
        type=validate_priority,
        help="Set or override (if using classtype) the default priority of the alert"
    )

    parser.add_argument(
        "--metadata",
        type=validate_metadata,
        help="Key value pairs, comma separated (e.g., 'key value, key value'), containing additional information about the rule"        
    )

    parser.add_argument(
        "--msg",
        type=validate_msg,
        help="Rule option describing the rule (must escape Snort reserved characters)"
    )

    args = parser.parse_args()

    if args.interactive or len(vars(args)) == 1:
        run_interactive()
    else:
        run(args)

if __name__ == "__main__":
    main()