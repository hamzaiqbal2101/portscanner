"""High-level scan orchestration with concurrent workers."""

import concurrent.futures
import socket
import time

from portscanner import tcp_scan, udp_scan, services
from portscanner.output import _iso

DEFAULT_THREADS = 100


def resolve(host):
    return socket.gethostbyname(host)


class PortScanner:
    def __init__(self, host, threads=DEFAULT_THREADS):
        self.host = host
        self.threads = max(1, threads)
        self.resolved_ip = None

    def _resolve(self):
        if self.resolved_ip is None:
            self.resolved_ip = resolve(self.host)
        return self.resolved_ip

    def scan_tcp_connect(self, ports, timeout=1.0):
        self._resolve()
        results = {}

        def probe(port):
            return port, tcp_scan.tcp_connect_scan(
                self.resolved_ip, port, timeout=timeout
            )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as pool:
            for port, is_open in pool.map(probe, ports):
                results[port] = is_open
        return results

    def scan_tcp_syn(self, ports, timeout=1.0):
        self._resolve()
        results = {}

        def probe(port):
            return port, tcp_scan.syn_scan(self.resolved_ip, port, timeout=timeout)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as pool:
            for port, is_open in pool.map(probe, ports):
                results[port] = is_open
        return results

    def scan_udp(self, ports, timeout=2.0):
        self._resolve()
        results = {}

        def probe(port):
            status, data = udp_scan.udp_scan(
                self.resolved_ip, port, timeout=timeout
            )
            return port, (status, data)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as pool:
            for port, result in pool.map(probe, ports):
                results[port] = result
        return results

    def detect_services(self, ports, timeout=3.0):
        self._resolve()
        results = {}

        def probe(port):
            service, version = services.grab_banner(
                self.resolved_ip, port, timeout=timeout
            )
            return port, (service, version)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as pool:
            for port, result in pool.map(probe, ports):
                results[port] = result
        return results


def run_scan(
    host,
    ports,
    scan_types=("tcp",),
    threads=DEFAULT_THREADS,
    timeout=1.0,
    udp_timeout=2.0,
    version_detect=False,
):
    """Execute the requested scans and return a normalized result dict."""
    scanner = PortScanner(host, threads=threads)
    started = time.time()
    started_iso = _iso()
    host_entry = {
        "host": host,
        "ip": scanner._resolve(),
        "ports": [],
    }

    port_set = set(ports)

    tcp_open = {}
    if "tcp" in scan_types or "syn" in scan_types:
        scan_type = "syn" if "syn" in scan_types else "tcp"
        if scan_type == "syn":
            tcp_open = scanner.scan_tcp_syn(port_set, timeout=timeout)
        else:
            tcp_open = scanner.scan_tcp_connect(port_set, timeout=timeout)

    udp_results = {}
    if "udp" in scan_types:
        udp_results = scanner.scan_udp(port_set, timeout=udp_timeout)

    for port in sorted(port_set):
        if port in tcp_open and tcp_open[port]:
            entry = {
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "service": services.default_service(port),
                "version": "",
            }
            host_entry["ports"].append(entry)
        elif port in udp_results:
            status, data = udp_results[port]
            entry = {
                "port": port,
                "protocol": "udp",
                "status": status,
                "service": services.default_service(port),
                "version": "",
            }
            if data:
                entry["version"] = _decode_bytes(data)
            host_entry["ports"].append(entry)

    if version_detect and tcp_open:
        open_ports = [p for p, open_flag in tcp_open.items() if open_flag]
        if open_ports:
            detected = scanner.detect_services(open_ports, timeout=timeout)
            for entry in host_entry["ports"]:
                if entry["protocol"] == "tcp":
                    service, version = detected.get(entry["port"], (None, None))
                    if service:
                        entry["service"] = service
                    if version:
                        entry["version"] = version

    finished_iso = _iso()
    duration = time.time() - started
    return {
        "target": host,
        "started": started_iso,
        "finished": finished_iso,
        "duration": round(duration, 3),
        "scan_type": "+".join(scan_types),
        "hosts": [host_entry],
    }


def _decode_bytes(data):
    try:
        return data.decode("utf-8", "replace")[:200]
    except Exception:
        return repr(data)[:200]