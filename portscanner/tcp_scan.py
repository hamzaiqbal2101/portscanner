"""TCP port scanning: full connect scan and raw SYN (half-open) scan."""

import os
import socket
import struct

TCP_TIMEOUT_DEFAULT = 2.0


def tcp_connect_scan(host, port, timeout=TCP_TIMEOUT_DEFAULT):
    """Attempt a full TCP three-way handshake.

    Reliable on any platform and needs no special privileges.
    Returns True when the target accepts the connection.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except (socket.error, OSError):
        return False
    finally:
        sock.close()


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_syn_packet(src, dst, sport, dport):
    ip_ihl_ver = 0x45
    ip_tos = 0
    ip_tot_len = 40
    ip_id = os.getpid() & 0xFFFF
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_checksum = 0
    ip_saddr = socket.inet_aton(src)
    ip_daddr = socket.inet_aton(dst)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_checksum,
        ip_saddr,
        ip_daddr,
    )
    ip_checksum = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_checksum,
        ip_saddr,
        ip_daddr,
    )

    seq = os.getpid() ^ (sport << 16) ^ dport
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        sport,
        dport,
        seq,
        0,
        5 << 4,
        0x02,
        5840,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        ip_saddr,
        ip_daddr,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    tcp_checksum = _checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        sport,
        dport,
        seq,
        0,
        5 << 4,
        0x02,
        5840,
        0,
        tcp_checksum,
    )
    return ip_header + tcp_header


def _parse_tcp_response(packet):
    if len(packet) < 54:
        return None
    ip_header = packet[0:20]
    proto = ip_header[9]
    if proto != socket.IPPROTO_TCP:
        return None
    tcp_header = packet[20:40]
    flags = struct.unpack("!H", tcp_header[12:14])[0]
    sport = struct.unpack("!H", tcp_header[0:2])[0]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    return src_ip, sport, flags


SYN_ACK = 0x12
RST = 0x14


def syn_scan(host, port, timeout=TCP_TIMEOUT_DEFAULT):
    """Half-open SYN scan using raw sockets.

    Requires root / Administrator privileges.
    On Windows, raw packet sending is permitted with admin rights but
    response capture needs an additional raw socket; if raw sockets are
    unavailable the function falls back to a TCP connect scan.
    """
    if not hasattr(socket, "IPPROTO_RAW"):
        return tcp_connect_scan(host, port, timeout)

    try:
        dst_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return False

    try:
        src_ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        src_ip = "0.0.0.0"

    sender = None
    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        import random

        sport = random.randint(49152, 65535)
        packet = _build_syn_packet(src_ip, dst_ip, sport, port)
        sender.sendto(packet, (dst_ip, port))
    except (socket.error, OSError, PermissionError):
        if sender:
            sender.close()
        return tcp_connect_scan(host, port, timeout)

    receiver = None
    try:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        receiver.settimeout(timeout)
        deadline = timeout
        while deadline > 0:
            receiver.settimeout(deadline)
            try:
                response, addr = receiver.recvfrom(65535)
            except socket.timeout:
                break
            parsed = _parse_tcp_response(response)
            if parsed and parsed[0] == dst_ip and parsed[1] == port:
                flags = parsed[2]
                if flags & 0x12 == 0x12:
                    return True
                if flags & 0x04:
                    return False
    except (socket.error, OSError, PermissionError):
        return tcp_connect_scan(host, port, timeout)
    finally:
        if receiver:
            receiver.close()
        if sender:
            sender.close()
    return False
