# SnortGen

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)


**SnortGen** is a CLI tool for generating [Snort](https://www.snort.org/) rules quickly, safely, and interactively — right from your terminal.

It supports all core Snort rule fields with input validation, auto-incremented SIDs, and options for advanced content matching. Ideal for security engineers, analysts, or red teamers who want to generate rules without memorizing syntax.

---

## Features

- Interactive CLI rule builder
- Input validation for protocol, IPs, ports, and modifiers
- Supports:
  - `content`, `nocase`, `offset`, `depth`
  - `flags`, `pcre` (Perl-compatible regex)
  - `classtype`, `priority`
  - `metadata` (structured + custom)
  - `reference` (e.g., CVEs or URLs)
- Auto-incrementing SID with file-backed state
- Saves rules to `rules/local.rules` by default

---

## Getting Started

### With Docker (Recommended)

```bash
git clone https://github.com/DryHop2/snortgen.git
cd snortgen
docker-compose build
docker-compose run --rm app
```

### Local Python
```
python main.py
```

## Example Rule Output
alert tcp any any -> $HOME_NET 80 (
    msg:"Suspicious download";
    content:"wget";
    nocase;
    offset:0;
    depth:60;
    flags:S;
    classtype:policy-violation;
    priority:2;
    metadata:attack_target server, deployment perimeter;
    reference:cve,2021-44228;
    sid:1000001;
    rev:1;
)

## Roadmap
Planned future enhancements:
* Rule file selection(web.rules, malware.rules, etc.)
* Command-line argument support
* JSON/CSV export
* Bulk rule generation from strutured input
* SID counter reset (with warnings)
* Configurable output settings

## Requirements
* Python 3.8+
* Docker (optional, for containerized use)

## License
MIT