import argparse

from snortsmith_rulegen._config import _load_config
from snortsmith_rulegen.snortsmith import run_interactive, run
from snortsmith_rulegen.batch import run_batch
from snortsmith_rulegen._utils import (
    _validate_protocol,
    _validate_ip,
    _validate_port,
    _validate_priority,
    _validate_flags,
    _validate_pcre,
    _validate_metadata,
    _validate_msg,
    _validate_reference,
    _argparse_type
)


def main():
    """
    Entry point for the Snortsmith CLI tool.

    Parses commandline arguments, loads configuation overrides, and routes execution to either
    interactive mode, batch mode, or single rule generation.
    """

    parser = argparse.ArgumentParser(
        prog="snortsmith",
        description=(
            "Snortsmith: An interactive CLI tool to generate Snort rules quickly.\n\n"
            "Snortsmith walks you through building a rule step-by-step. "
            "It supports common fields like protocol, IP, port, content matching, PCRE, flags, "
            "classtype, metadata, and more. SID assignment is automatic and rules are saved to "
            "'rules/local.rules' by default.\n\n"
            "Designed for security engineers, analysts, and anyone who wants to generate Snort rules "
            "without memorizing syntax."
        ),
        epilog="More info: https://github.com/DryHop2/snortsmith",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # CLI mode switches
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive prompt mode"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Snortsmith 1.0.0"
    )

    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Display the current configuration file and resolved keys"
    )

    # Basic rule structure
    parser.add_argument(
        "--proto",
        type=_argparse_type(_validate_protocol),
        help="Protocol to use for the rule (default: tcp; options: tcp, udp, icmp, ip)"
    )

    parser.add_argument(
        "--src-ip",
        type=_argparse_type(_validate_ip),
        help="Source IP to use for the rule (default: any)"
    )

    parser.add_argument(
        "--src-port",
        type=_argparse_type(_validate_port),
        help="Source port to use for the rule (default: any)"
    )

    parser.add_argument(
        "--dst-ip",
        type=_argparse_type(_validate_ip),
        help="Destination IP to use for the rule (default: $HOME_NET)"
    )

    parser.add_argument(
        "--dst-port",
        type=_argparse_type(_validate_port),
        help="Destination port to use for the rule (default: 80)"
    )

    # Matching logic
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
        type=_argparse_type(_validate_flags),
        help="TCP flags to match for rule (e.g., S, SA, *SA, SF,CE)"
    )

    parser.add_argument(
        "--pcre",
        type=_argparse_type(_validate_pcre),
        help="Perl-compatible regex pattern (e.g., /user.*=root/i)"
    )

    # Rule metadata
    parser.add_argument(
        "--classtype",
        type=str,
        help="Classification to indicate the type of attack suspected in the event"
    )

    parser.add_argument(
        "--priority",
        type=_argparse_type(_validate_priority),
        help="Set or override (if using classtype) the default priority of the alert"
    )

    parser.add_argument(
        "--metadata",
        type=_argparse_type(_validate_metadata),
        help="Key value pairs, comma separated (e.g., 'key value, key value'), containing additional information about the rule"        
    )

    parser.add_argument(
        "--msg",
        type=_argparse_type(_validate_msg),
        help="Rule option describing the rule (must escape Snort reserved characters)"
    )

    parser.add_argument(
        "--reference",
        type=_argparse_type(_validate_reference),
        help="Provides additional context to Snort rule in form of scheme,id (e.g., url,www.example.com)"
    )

    parser.add_argument(
        "--comment",
        type=str,
        help="Optional comment to append after rule (e.g., '# Investigated on 2025-07-29)"
    )

    # Output and behavior modifiers
    parser.add_argument(
        "--outfile",
        type=str,
        help="Path to save generated Snort rule (default: rules/local.rules)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose outplut (e.g., file and directory warnings, internal steps)"
    )

    parser.add_argument(
        "--batch",
        type=str,
        help="Path to JSON file with batch rule definitions"
    )

    parser.add_argument(
        "--sid",
        type=int,
        help="Manually specify a SID. If that SID exists in the output file, the revision will be incremented. (Can overwrite rules)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview rules(s) without writing to file"
    )

    args = parser.parse_args()
    config = _load_config()

    # Verbose config display if applicable
    if args.verbose and config:
        print(f"Using config overrides from: {config.get('__source__', 'unknown')}")
        for key, value in config.items():
            if not key.startswith("__"):
                print(f"  {key} = {value}")

    if args.show_config:
        if not config:
            print("No configuration file found.")
        else:
            print(f"Using config from: {config.get('__source__', 'unknown')}")
            for key, value in config.items():
                if not key.startswith("__"):
                    print(f"  {key} = {value}")
        return
    
    # Execution flow: batch > interactive > CLI

    try:
        if args.batch:
            run_batch(
                filepath=args.batch,
                outfile=args.outfile,
                verbose=args.verbose,
                config=config
            )
        elif args.interactive or len(vars(args)) == 1:
            run_interactive()
        else:
            run(args, config)
    except Exception as e:
        print(F"[ERROR] An error occurred while running Snortsmith: {e}")
        exit(1)

if __name__ == "__main__":
    main()