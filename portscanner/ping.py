"""Host discovery via ICMP echo (ping) sweep, with a TCP fallback."""

import os
import socket
import struct
import subprocess
import sys

PING_TIMEOUT_DEFAULT = 1.0


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _icmp_ping(host, timeout=PING_TIMEOUT_DEFAULT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    try:
        ident = os.getpid() & 0xFFFF
        seq = 1
        payload = struct.pack("!HH", ident, seq) + b"P" * 32
        header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        chk = _checksum(header + payload)
        header = struct.pack("!BBHHH", 8, 0, chk, ident, seq)
        packet = header + payload

        sock.sendto(packet, (host, 1))
        deadline = timeout
        while deadline > 0:
            sock.settimeout(deadline)
            try:
                response, addr = sock.recvfrom(2048)
            except socket.timeout:
                return False
            if len(response) < 28:
                continue
            icmp_type = response[20]
            if icmp_type == 0:
                return True
    except (socket.error, OSError, PermissionError):
        return _ping_fallback(host, timeout)
    finally:
        sock.close()
    return False


def _ping_fallback(host, timeout=PING_TIMEOUT_DEFAULT):
    """Fallback using the system ping command (Windows needs no admin)."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
        creationflags = 0
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            timeout=timeout + 5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_host(host, timeout=PING_TIMEOUT_DEFAULT):
    """Return True if the host answers an ICMP echo request."""
    return _icmp_ping(host, timeout)


def sweep(subnet_prefix):
    """Expand a dotted subnet prefix and return a list of host IPs.

    Accepts "192.168.1" or "192.168.1.0/24". CIDR ranges beyond a /16
    are rejected to avoid runaway scans.
    """
    if "/" in subnet_prefix:
        ip_part, _, cidr = subnet_prefix.partition("/")
        cidr = int(cidr)
        octets = [int(x) for x in ip_part.split(".")]
        if cidr < 16:
            raise ValueError("CIDR prefix must be >= 16 for a sweep")
        if len(octets) != 4:
            raise ValueError("Invalid IP address in CIDR")
        import ipaddress

        network = ipaddress.ip_network(f"{ip_part}/{cidr}", strict=False)
        return [str(ip) for ip in network.hosts()]
    octets = [int(x) for x in subnet_prefix.split(".")]
    if len(octets) not in (1, 2, 3, 4):
        raise ValueError("Invalid subnet prefix")
    if len(octets) == 4:
        return [subnet_prefix]
    hosts = []
    for host_octet in range(1, 256):
        hosts.append(".".join([str(o) for o in octets] + [str(host_octet)]))
    return hosts