import argparse

from snort_rulegen.snortgen import run, run_interactive


def main():
    parser = argparse.ArgumentParser(
        prog="snortgen",
        description=(
            "SnortGen: An interactive CLI tool to generate Snort rules quickly.\n\n"
            "SnortGen walks you through building a rule step-by-step. "
            "It supports common fields like protocol, IP, port, content matching, PRCR, flags, "
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

    args = parser.parse_args()

    if args.interactive or len(vars(args)) == 1:
        run_interactive()
    else:
        run(args)

if __name__ == "__main__":
    main()