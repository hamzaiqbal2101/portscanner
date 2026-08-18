"""Command-line interface for the port scanner."""

import argparse
import sys
import time

from portscanner import __version__
from portscanner.output import to_csv, to_json
from portscanner.ping import ping_host, sweep


def parse_ports(spec):
    """Parse '80', '22,443', '1-1000', or a mix like '22,80-90,443'."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            try:
                start, end = int(start), int(end)
            except ValueError:
                raise argparse.ArgumentTypeError(f"invalid port range: {part}")
            if not (0 <= start <= 65535 and 0 <= end <= 65535) or start > end:
                raise argparse.ArgumentTypeError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise argparse.ArgumentTypeError(f"invalid port: {part}")
            if not 0 <= port <= 65535:
                raise argparse.ArgumentTypeError(f"port out of range: {part}")
            ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("no ports specified")
    return sorted(ports)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="A pure-Python port scanner for network security analysis.",
        epilog=(
            "Examples:\n"
            "  portscanner 192.168.1.1\n"
            "  portscanner scanme.example.org -p 1-1000 --threads 200\n"
            "  portscanner 10.0.0.5 -p 22,80,443 -s tcp --service -o report.json\n"
            "  portscanner --ping 192.168.1.1\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "target",
        nargs="?",
        help="hostname, IP, or subnet prefix to sweep (e.g. 192.168.1 or 10.0.0.0/24)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        metavar="SPEC",
        help="ports to scan: '80', '22,80-90,443' (default: 1-1000)",
    )
    parser.add_argument(
        "-s",
        "--scan",
        default="tcp",
        choices=("tcp", "syn", "udp", "tcp+udp", "all"),
        help="scan type (default: tcp)",
    )
    parser.add_argument(
        "--ping",
        action="store_true",
        help="ping sweep the target subnet first, then scan only live hosts",
    )
    parser.add_argument(
        "--service",
        "--version-detection",
        dest="service",
        action="store_true",
        help="perform service and version detection on open TCP ports",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="TCP connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--udp-timeout",
        type=float,
        default=2.0,
        help="UDP scan timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="number of concurrent workers (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write results to FILE (JSON or CSV by extension)",
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="only show open ports in the console report",
    )
    return parser


def _print_results(results, open_only=False):
    for host in results["hosts"]:
        print(f"\nHost: {host['host']} ({host['ip']})")
        ports = host["ports"]
        if not ports:
            print("  No open ports found.")
            continue
        print(f"  {'PORT':<8}{'STATE':<18}{'SERVICE':<16}{'VERSION'}")
        for entry in ports:
            if open_only and entry["status"] != "open":
                continue
            version = entry.get("version") or ""
            print(
                f"  {entry['port']}/{entry['protocol']:<6}"
                f"{entry['status']:<18}"
                f"{(entry.get('service') or ''):<16}{version}"
            )
    print(
        f"\nScan finished in {results['duration']}s "
        f"({results['scan_type']})."
    )


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.target:
        parser.error("a target host or subnet is required")

    if args.scan == "all":
        scan_types = ("tcp", "udp")
    elif args.scan == "tcp+udp":
        scan_types = ("tcp", "udp")
    else:
        scan_types = (args.scan,)

    try:
        ports = parse_ports(args.ports)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    if args.ping:
        try:
            hosts = sweep(args.target)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Ping sweeping {len(hosts)} host(s) in {args.target}...")
        live = [h for h in hosts if ping_host(h, timeout=args.timeout)]
        print(f"Found {len(live)} live host(s).")
        if not live:
            print("Nothing to scan.")
            return 0
        targets = live
    else:
        targets = [args.target]

    from portscanner.scanner import run_scan

    all_results = None
    for i, target in enumerate(targets):
        if len(targets) > 1:
            print(f"\n=== Scanning {target} ({i + 1}/{len(targets)}) ===")
        results = run_scan(
            host=target,
            ports=ports,
            scan_types=scan_types,
            threads=args.threads,
            timeout=args.timeout,
            udp_timeout=args.udp_timeout,
            version_detect=args.service,
        )
        if all_results is None:
            all_results = results
        else:
            all_results["hosts"].extend(results["hosts"])
            all_results["duration"] = round(
                all_results["duration"] + results["duration"], 3
            )
        _print_results(results, open_only=args.open_only)

    if args.output:
        if args.output.lower().endswith(".csv"):
            to_csv(all_results, args.output)
        else:
            to_json(all_results, args.output)
        print(f"Results written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())