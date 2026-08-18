# portscanner

A complete, pure-Python network port scanner for cybersecurity analysis.
No third-party dependencies — it uses only the standard library.

## Features

- **TCP connect scan** — full three-way handshake; works everywhere, no privileges needed.
- **SYN (half-open) scan** — raw-socket SYN packets; requires root/admin (falls back to a connect scan when raw sockets are unavailable, e.g. unprivileged Windows).
- **UDP scan** — sends per-service probes and detects ICMP "port unreachable" replies.
- **Ping sweep** — ICMP host discovery over a subnet, with a `ping`-command fallback for unprivileged Windows.
- **Service / version detection** — banner grabbing on open TCP ports.
- **Threading** — concurrent scanning via `ThreadPoolExecutor`.
- **Output** — human-readable console report, JSON, or CSV.

## Installation

```bash
pip install -e .
```

No extra dependencies are required. Python 3.8+.

## Usage

```bash
# Scan the first 1000 TCP ports of a host
python -m portscanner scanme.example.org

# Scan specific ports with a timeout
python -m portscanner 192.168.1.5 -p 22,80,443 -t 2

# Scan a port range with many threads
python -m portscanner 10.0.0.5 -p 1-10000 --threads 250

# UDP scan plus service detection, save to JSON
python -m portscanner 10.0.0.5 -p 53,123,161 -s udp --service -o report.json

# Ping sweep a /24, then scan only live hosts
python -m portscanner --ping 192.168.1.1

# Mixed TCP + UDP scan, CSV export
python -m portscanner 192.168.1.1 -s tcp+udp -p 1-1000 -o report.csv
```

### Command-line options

| Option | Description |
| --- | --- |
| `target` | hostname, IP, or subnet prefix (e.g. `192.168.1` or `10.0.0.0/24`) |
| `-p, --ports` | port spec: `80`, `22,80-90,443` (default `1-1000`) |
| `-s, --scan` | `tcp` (default), `syn`, `udp`, `tcp+udp`, or `all` |
| `--ping` | ping sweep the target first, scan only live hosts |
| `--service` | enable service/version detection on open TCP ports |
| `-t, --timeout` | TCP timeout in seconds (default `1.0`) |
| `--udp-timeout` | UDP timeout in seconds (default `2.0`) |
| `--threads` | concurrent workers (default `100`) |
| `-o, --output` | write results to a `.json` or `.csv` file |
| `--open-only` | show only open ports in the console report |

## Legal / ethical note

Scanning systems you do not own, or without authorization, is illegal in
most jurisdictions. Use this tool only on your own infrastructure, lab
machines, or targets you have explicit permission to test.

## Project layout

```
portscanner/
├── __init__.py       package metadata
├── __main__.py       python -m entry point
├── cli.py            argument parsing and console reporting
├── scanner.py        orchestration + concurrency
├── tcp_scan.py       TCP connect + raw SYN scans
├── udp_scan.py       UDP scan with ICMP unreachable detection
├── ping.py           ICMP ping + subnet sweep
├── services.py       service/version detection (banner grabbing)
└── output.py         JSON / CSV export
```