<div align="center">

# 🔍 portscanner

**A pure-Python, zero-dependency network port scanner for security analysis and penetration testing.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/hamzaiqbal2101/portscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hamzaiqbal2101/portscanner/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-35%20passing-brightgreen)](#-testing)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Scan Types](#-scan-types)
- [Output Formats](#-output-formats)
- [Command-Line Reference](#-command-line-reference)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Limitations](#-limitations)
- [Ethical & Legal Notice](#-ethical--legal-notice)
- [License](#-license)

---

## 🔭 Overview

`portscanner` is a complete, self-contained network reconnaissance tool built entirely on the
Python standard library — **no third-party dependencies required**. It performs full TCP,
half-open SYN, and UDP scans, discovers live hosts on a subnet, fingerprints services via
banner grabbing, and exports results in JSON or CSV.

It is designed both as a practical utility and as a reference implementation for learning
how the different port-scanning techniques work under the hood.

This is the fifth project in a cybersecurity portfolio:

1. [Password Strength Checker](https://github.com/hamzaiqbal2101/password-strength-checker)
2. [File Integrity Checker](https://github.com/hamzaiqbal2101/file-integrity-checker)
3. [File Encryptor](https://github.com/hamzaiqbal2101/file-encryptor)
4. [Subdomain Enumerator](https://github.com/hamzaiqbal2101/subdomain-enumerator)
5. **Port Scanner** (this project)

---

## ✨ Features

| Feature | Description |
| --- | --- |
| **TCP connect scan** | Full three-way handshake. Reliable on every platform, no privileges needed. |
| **SYN (half-open) scan** | Raw-socket SYN packets for faster, stealthier scans (requires root/admin). |
| **UDP scan** | Per-service probe payloads plus ICMP *port unreachable* detection. |
| **Ping sweep** | ICMP host discovery across a subnet with an automatic `ping`-command fallback. |
| **Service/version detection** | Banner grabbing to identify services and their versions. |
| **Concurrency** | Threaded scanning via `ThreadPoolExecutor` for high throughput. |
| **Flexible port specs** | Single ports, lists, ranges, or any mix — e.g. `22,80-90,443`. |
| **Multiple output formats** | Human-readable console report, JSON, and CSV. |
| **Zero dependencies** | Uses only the Python standard library. |

---

## 📦 Installation

### Prerequisites

- **Python 3.10 or newer** — [download](https://www.python.org/downloads/)

### Option 1 — Install as a package (recommended)

```bash
pip install -e .
```

This also installs the `portscanner` console command:

```bash
portscanner --help
```

### Option 2 — Run directly without installing

```bash
python -m portscanner --help
```

> **Note:** No third-party packages are installed by this project. All functionality is
> provided by the standard library.

---

## 🚀 Quick Start

```bash
# Scan the first 1000 TCP ports of a host
python -m portscanner scanme.example.org

# Scan specific ports
python -m portscanner 192.168.1.5 -p 22,80,443

# Scan a port range with aggressive concurrency
python -m portscanner 10.0.0.5 -p 1-10000 --threads 250

# Scan UDP ports and fingerprint services, save to JSON
python -m portscanner 10.0.0.5 -p 53,123,161 -s udp --service -o report.json

# Discover live hosts on a subnet, then scan only those
python -m portscanner --ping 192.168.1.1

# Mixed TCP + UDP scan exported to CSV
python -m portscanner 192.168.1.1 -s tcp+udp -p 1-1000 -o report.csv
```

### Example output

```
Host: 127.0.0.1 (127.0.0.1)
  PORT       STATE             SERVICE         VERSION
  22/tcp     open              ssh
  80/tcp     open              http            HTTP/1.0 200 OK Server: SimpleHTTP/0.6
  8080/tcp   open              http-proxy
  53/udp     closed            dns

Scan finished in 0.553s (tcp).
```

---

## 🧭 Usage

### Specifying targets

- **Hostname** — `scanme.example.org`
- **IP address** — `192.168.1.5`
- **Subnet prefix** — `192.168.1` (last octet swept) or CIDR notation like `10.0.0.0/24`
  (prefixes shorter than `/16` are rejected to prevent runaway scans)

### Specifying ports

The `-p/--ports` flag accepts a comma-separated list where each item is a single port or a
range:

| Input | Ports scanned |
| --- | --- |
| `-p 80` | `80` |
| `-p 22,443,8080` | `22`, `443`, `8080` |
| `-p 1-1000` | `1` through `1000` |
| `-p 22,80-90,443` | `22`, `80`–`90`, `443` |

Default is `1-1000`.

---

## 🧬 Scan Types

| Flag | Technique | Privileges | How it works |
| --- | --- | --- | --- |
| `-s tcp` *(default)* | TCP connect | None | Completes the full TCP three-way handshake. Highest accuracy, easily logged. |
| `-s syn` | SYN (half-open) | root/admin | Sends a raw SYN packet and inspects the response. Never completes the handshake — faster and less intrusive. Falls back to a connect scan when raw sockets are unavailable. |
| `-s udp` | UDP | None | Sends UDP probes (per-service payloads for DNS, NTP, SNMP, etc.) and detects ICMP *port unreachable* replies. Silence is reported as `open_or_filtered`. |
| `-s tcp+udp` | TCP + UDP | — | Runs both scans in one pass. |
| `-s all` | TCP + UDP | — | Alias for `tcp+udp`. |

### UDP states

UDP has no handshake, so results are interpreted differently:

- **open** — the target replied with data.
- **open_or_filtered** — no reply was received (open or filtered by a firewall).
- **closed** — an ICMP *port unreachable* message was received.

---

## 📄 Output Formats

### Console

The default human-readable report is printed to the terminal.

### JSON (`-o report.json`)

```json
{
  "scan": {
    "target": "127.0.0.1",
    "started": "2026-08-18T08:17:40",
    "finished": "2026-08-18T08:17:40",
    "duration_seconds": 0.55,
    "scan_type": "tcp"
  },
  "hosts": [
    {
      "host": "127.0.0.1",
      "ip": "127.0.0.1",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "status": "open",
          "service": "http",
          "version": "HTTP/1.0 200 OK Server: SimpleHTTP/0.6"
        }
      ]
    }
  ]
}
```

### CSV (`-o report.csv`)

Columns: `host,port,protocol,status,service,version`

---

## 🛠 Command-Line Reference

```
usage: portscanner [-h] [--version] [-p SPEC] [-s {tcp,syn,udp,tcp+udp,all}]
                   [--ping] [--service] [-t TIMEOUT]
                   [--udp-timeout UDP_TIMEOUT] [--threads THREADS] [-o FILE]
                   [--open-only]
                   [target]
```

| Option | Description | Default |
| --- | --- | --- |
| `target` | Hostname, IP, or subnet prefix to scan | required |
| `-p, --ports <SPEC>` | Port spec: `80`, `22,80-90,443` | `1-1000` |
| `-s, --scan <TYPE>` | Scan type: `tcp`, `syn`, `udp`, `tcp+udp`, `all` | `tcp` |
| `--ping` | Ping-sweep the target first, scan only live hosts | off |
| `--service` | Enable service/version detection on open TCP ports | off |
| `-t, --timeout <SEC>` | TCP connection timeout | `1.0` |
| `--udp-timeout <SEC>` | UDP scan timeout | `2.0` |
| `--threads <N>` | Number of concurrent workers | `100` |
| `-o, --output <FILE>` | Export results to a `.json` or `.csv` file | — |
| `--open-only` | Show only open ports in the console report | off |
| `--version` | Print the version and exit | — |
| `-h, --help` | Show the full help text | — |

---

## 📁 Project Structure

```
portscanner/
├── portscanner/
│   ├── __init__.py       Package metadata (version)
│   ├── __main__.py       `python -m portscanner` entry point
│   ├── cli.py            Argument parsing and console reporting
│   ├── scanner.py        Scan orchestration and concurrency
│   ├── tcp_scan.py       TCP connect + raw SYN scanning
│   ├── udp_scan.py       UDP scanning with ICMP unreachable detection
│   ├── ping.py           ICMP ping and subnet sweep
│   ├── services.py       Service/version detection (banner grabbing)
│   └── output.py         JSON / CSV export
├── tests/
│   └── test_portscanner.py  Pytest suite (35 tests, network fully mocked)
├── .github/workflows/
│   └── ci.yml            CI: pytest on Python 3.10–3.12
├── pyproject.toml        Packaging and console-script definition
├── .gitignore            Ignored files (cache, test artifacts)
└── README.md             This file
```

---

## 🧪 Testing

```bash
# Install the test runner (only dependency, dev-only)
pip install pytest

# Run the full test suite (35 tests, fully mocked — no network needed)
python -m pytest -v
```

Manual smoke tests:

```bash
# Verify the CLI is importable and functional
python -m portscanner --version

# Run a quick scan against your local machine (safe)
python -m portscanner 127.0.0.1 -p 1-100

# Scan a local service and confirm service detection
python -m http.server 8080 &
python -m portscanner 127.0.0.1 -p 8080 --service
```

---

## ⚠️ Limitations

- **SYN scan** requires root/Administrator privileges and full raw-socket access. On
  unprivileged systems (e.g. default Windows), it transparently falls back to a TCP connect
  scan.
- **UDP results** are inherently ambiguous; silence means *open* or *filtered*.
- Scanning very large ranges (`1-65535`) on many hosts can take a long time — tune
  `--threads` and timeouts to your network.
- Subnet sweeps are limited to `/16` and shorter prefixes to avoid unintended large scans.

---

## 🚨 Ethical & Legal Notice

> **This tool is for authorized security testing and education only.**
>
> Scanning networks or systems you do not own, or without explicit written permission,
> may be illegal in your jurisdiction and can carry criminal or civil penalties.
> Use this software exclusively on your own infrastructure, lab machines, or targets you
> have been granted permission to test. The author assumes no liability for misuse.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with 🛡️ for the security community. Use responsibly.

</div>