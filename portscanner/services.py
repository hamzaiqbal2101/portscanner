"""Service and version detection via banner grabbing."""

import socket

BANNER_TIMEOUT_DEFAULT = 3.0

# Well-known service names for common ports.
WELL_KNOWN_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 514: "syslog", 587: "smtp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks-proxy",
    1194: "openvpn", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2181: "zookeeper", 2375: "docker", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 4369: "erpc", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 7001: "weblogic",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 5000: "upnp",
}

SERVICE_PROBES = {
    21: b"QUIT\r\n",
    22: b"\n",
    23: b"\r\n",
    25: b"EHLO scanner.local\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"QUIT\r\n",
    143: b"a1 LOGOUT\r\n",
    220: b"\r\n",
    443: b"\x16\x03\x01\x00\x02\x01\x00",
    445: b"\x00\x00\x00\x00",
    587: b"EHLO scanner.local\r\n",
    993: b"a1 LOGOUT\r\n",
    995: b"QUIT\r\n",
    3306: b"\x00\x00\x00\x00",
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    5900: b"\x00",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"\x16\x03\x01\x00\x02\x01\x00",
    9200: b"GET / HTTP/1.0\r\n\r\n",
}

DEFAULT_BANNER_PROBE = b"\r\n"


def _clean(data):
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return repr(data)
    return " ".join(text.split())[:200]


def default_service(port):
    return WELL_KNOWN_SERVICES.get(port)


def grab_banner(host, port, timeout=BANNER_TIMEOUT_DEFAULT):
    """Connect and read a service banner or respond to a probe.

    Returns (service_name, version_string) or (None, None).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(SERVICE_PROBES.get(port, DEFAULT_BANNER_PROBE))
        data = sock.recv(2048)
        if not data:
            return None, None
        text = _clean(data)
        return WELL_KNOWN_SERVICES.get(port, "unknown"), text
    except (socket.error, OSError, socket.timeout):
        try:
            sock.settimeout(timeout)
            data = sock.recv(2048)
            if data:
                return WELL_KNOWN_SERVICES.get(port, "unknown"), _clean(data)
        except (socket.error, OSError, socket.timeout):
            pass
        return None, None
    finally:
        sock.close()