# NetScope

## Overview

NetScope is a compact Python command-line toolkit for network diagnostics and defensive security checks.

## Features

- TCP port scanning and optional banner grabbing
- DNS and reverse-DNS lookup
- HTTP status and security-header analysis
- TLS certificate inspection
- Ping, traceroute, subnet, and local-network helpers
- JSON and text result export

## Requirements

Python 3.11 or newer. NetScope uses the Python standard library; ping and traceroute features also depend on platform utilities.

## Running

```bash
python main.py scan example.com
python main.py dns example.com
python main.py ssl example.com
python main.py headers https://example.com
python main.py subnet 192.168.1.0/24
```

## Configuration

Use command-line options for ports, output paths, formats, verbosity, and color behavior. Run `python main.py --help` for the complete command list.

## Security

Scan only authorized targets and protect exported results, which can reveal network and service details.

## Limitations

ICMP, traceroute, banner collection, and port results can be affected by operating-system permissions, firewalls, proxies, and rate limits.

## Disclaimer

For diagnostics, education, and authorized defensive assessment only.
