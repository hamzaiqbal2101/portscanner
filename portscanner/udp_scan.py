"""UDP port scanning.

UDP is connectionless so an "open" port either answers or stays silent.
A closed port typically triggers an ICMP "port unreachable" reply.
Where ICMP parsing is unavailable (unprivileged Windows), silence is
treated as open/filtered and the result is marked as such.
"""

import socket
import struct

UDP_TIMEOUT_DEFAULT = 2.0

# Per-port probe payloads for common UDP services.
UDP_PROBES = {
    53: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x03nic\x00\x00\x01\x00\x01",
    123: b"\x1b" + b"\x00" * 47,
    137: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19"
         b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09"
         b"\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00",
}

UNREACHABLE_MSG = 3
ICMP_PORT_UNREACHABLE = 3


def _send_udp(host, port, timeout=UDP_TIMEOUT_DEFAULT, probe=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        payload = probe if probe is not None else b"\x00"
        sock.sendto(payload, (host, port))
        try:
            data, addr = sock.recvfrom(2048)
            return "open", data, addr
        except socket.timeout:
            return "open_or_filtered", None, None
    except socket.error:
        return "closed", None, None
    finally:
        sock.close()


def _listen_icmp(host, port, timeout=UDP_TIMEOUT_DEFAULT):
    """Try to catch an ICMP port-unreachable reply. Best-effort on Windows."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (socket.error, OSError, PermissionError):
        return False
    sock.settimeout(timeout)
    deadline = timeout
    try:
        while deadline > 0:
            sock.settimeout(deadline)
            try:
                packet, addr = sock.recvfrom(2048)
            except socket.timeout:
                return False
            if len(packet) < 28:
                continue
            icmp_type = packet[20]
            if icmp_type != UNREACHABLE_MSG:
                continue
            icmp_code = packet[21]
            original_port = struct.unpack("!H", packet[50:52])[0]
            if icmp_code == ICMP_PORT_UNREACHABLE and original_port == port:
                return True
    except socket.error:
        return False
    finally:
        sock.close()
    return False


def udp_scan(host, port, timeout=UDP_TIMEOUT_DEFAULT, probe=None):
    """Scan a single UDP port.

    Returns a tuple (status, service_data):
      ("open", data)            - a reply was received
      ("open_or_filtered", None)- silence (open or filtered)
      ("closed", None)          - ICMP port unreachable detected
    """
    probe = probe or UDP_PROBES.get(port)
    status, data, addr = _send_udp(host, port, timeout, probe)
    if status == "closed":
        return status, None
    if status == "open_or_filtered":
        if _listen_icmp(host, port, timeout):
            return "closed", None
        return status, None
    return status, data
