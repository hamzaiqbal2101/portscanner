"""Test suite for portscanner: CLI parsing, scanning orchestration, output, and services."""

import argparse
import csv
import json
import re
import socket
from unittest import mock

import pytest

from portscanner import cli, output, ping, scanner, services, tcp_scan


# ---------------------------------------------------------------------------
# cli.parse_ports
# ---------------------------------------------------------------------------

class TestParsePorts:
    def test_single_port(self):
        assert cli.parse_ports("80") == [80]

    def test_comma_list(self):
        assert cli.parse_ports("22,443") == [22, 443]

    def test_range(self):
        assert cli.parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixed_spec(self):
        assert cli.parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]

    def test_deduplicates_and_sorts(self):
        assert cli.parse_ports("443,22,443") == [22, 443]

    def test_whitespace_tolerated(self):
        assert cli.parse_ports(" 22 , 80-81 ") == [22, 80, 81]

    def test_invalid_port(self):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports("abc")

    def test_port_out_of_range(self):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports("70000")

    def test_invalid_range(self):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports("100-50")

    def test_empty_spec(self):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_ports("")


# ---------------------------------------------------------------------------
# cli.build_parser / cli.main
# ---------------------------------------------------------------------------

class TestCli:
    def test_parser_defaults(self):
        args = cli.build_parser().parse_args(["example.com"])
        assert args.target == "example.com"
        assert args.ports == "1-1000"
        assert args.scan == "tcp"
        assert args.threads == 100
        assert args.timeout == 1.0
        assert args.service is False

    def test_parser_scan_choices(self):
        for choice in ("tcp", "syn", "udp", "tcp+udp", "all"):
            args = cli.build_parser().parse_args(["example.com", "-s", choice])
            assert args.scan == choice

    def test_parser_rejects_bad_scan_type(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["example.com", "-s", "bogus"])

    def test_main_requires_target(self):
        with pytest.raises(SystemExit):
            cli.main([])

    def test_main_rejects_bad_ports(self):
        with pytest.raises(SystemExit):
            cli.main(["example.com", "-p", "99999"])


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------

class TestServices:
    def test_default_service_known(self):
        assert services.default_service(22) == "ssh"
        assert services.default_service(443) == "https"
        assert services.default_service(3306) == "mysql"

    def test_default_service_unknown(self):
        assert services.default_service(59999) is None

    def _fake_socket(self, banner):
        sock = mock.Mock()
        sock.recv.return_value = banner
        return sock

    def test_grab_banner_success(self):
        fake = self._fake_socket(b"SSH-2.0-OpenSSH_9.0\r\n")
        with mock.patch("socket.socket", return_value=fake):
            service, version = services.grab_banner("127.0.0.1", 22)
        assert service == "ssh"
        assert "OpenSSH" in version

    def test_grab_banner_unknown_port(self):
        fake = self._fake_socket(b"HELLO\r\n")
        with mock.patch("socket.socket", return_value=fake):
            service, version = services.grab_banner("127.0.0.1", 59999)
        assert service == "unknown"
        assert "HELLO" in version

    def test_grab_banner_connection_refused(self):
        fake = mock.Mock()
        fake.connect.side_effect = socket.error("refused")
        fake.recv.side_effect = socket.error("refused")
        with mock.patch("socket.socket", return_value=fake):
            assert services.grab_banner("127.0.0.1", 22) == (None, None)


# ---------------------------------------------------------------------------
# tcp_scan
# ---------------------------------------------------------------------------

class TestTcpScan:
    def test_connect_open(self):
        fake = mock.Mock()
        fake.connect_ex.return_value = 0
        with mock.patch("socket.socket", return_value=fake):
            assert tcp_scan.tcp_connect_scan("127.0.0.1", 80) is True

    def test_connect_closed(self):
        fake = mock.Mock()
        fake.connect_ex.return_value = 111  # ECONNREFUSED
        with mock.patch("socket.socket", return_value=fake):
            assert tcp_scan.tcp_connect_scan("127.0.0.1", 81) is False

    def test_connect_socket_error(self):
        with mock.patch("socket.socket", side_effect=socket.error("boom")):
            assert tcp_scan.tcp_connect_scan("127.0.0.1", 80) is False


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def _sample_results():
    return {
        "target": "example.com",
        "started": "2026-01-01T00:00:00",
        "finished": "2026-01-01T00:00:01",
        "duration": 1.234,
        "scan_type": "tcp",
        "hosts": [
            {
                "host": "example.com",
                "ip": "93.184.216.34",
                "ports": [
                    {"port": 80, "protocol": "tcp", "status": "open",
                     "service": "http", "version": "nginx"},
                    {"port": 443, "protocol": "tcp", "status": "open",
                     "service": "https", "version": ""},
                ],
            }
        ],
    }


class TestOutput:
    def test_to_json_roundtrip(self, tmp_path):
        path = tmp_path / "report.json"
        output.to_json(_sample_results(), str(path))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan"]["target"] == "example.com"
        assert data["scan"]["scan_type"] == "tcp"
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["ports"][0]["port"] == 80

    def test_to_csv_rows(self, tmp_path):
        path = tmp_path / "report.csv"
        output.to_csv(_sample_results(), str(path))
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert [r["port"] for r in rows] == ["80", "443"]
        assert rows[0]["host"] == "example.com"
        assert rows[0]["service"] == "http"

    def test_iso_format(self):
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
                            output._iso())


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------

class TestPing:
    def test_sweep_dotted_prefix(self):
        hosts = ping.sweep("192.168.1")
        assert len(hosts) == 255
        assert hosts[0] == "192.168.1.1"
        assert hosts[-1] == "192.168.1.255"

    def test_sweep_single_ip(self):
        assert ping.sweep("10.0.0.5") == ["10.0.0.5"]

    def test_sweep_cidr(self):
        hosts = ping.sweep("10.0.0.0/30")
        assert hosts == ["10.0.0.1", "10.0.0.2"]

    def test_sweep_rejects_wide_cidr(self):
        with pytest.raises(ValueError):
            ping.sweep("10.0.0.0/8")

    def test_checksum_known_vector(self):
        # Empty input -> complement of zero fold.
        assert ping._checksum(b"") == 0xFFFF


# ---------------------------------------------------------------------------
# scanner orchestration (network fully mocked)
# ---------------------------------------------------------------------------

class TestScanner:
    def _patch_network(self):
        resolve = mock.patch("portscanner.scanner.resolve",
                             return_value="127.0.0.1")
        connect = mock.patch(
            "portscanner.tcp_scan.tcp_connect_scan",
            side_effect=lambda host, port, timeout=2.0: port == 80,
        )
        return resolve, connect

    def test_scan_tcp_connect_aggregates(self):
        resolve, connect = self._patch_network()
        with resolve, connect:
            ps = scanner.PortScanner("example.com", threads=2)
            results = ps.scan_tcp_connect([80, 81, 443])
        assert results == {80: True, 81: False, 443: False}

    def test_threads_minimum_one(self):
        ps = scanner.PortScanner("example.com", threads=0)
        assert ps.threads == 1

    def test_run_scan_result_shape(self):
        resolve, connect = self._patch_network()
        with resolve, connect:
            results = scanner.run_scan("example.com", [80, 81],
                                       scan_types=("tcp",), threads=2)
        assert results["target"] == "example.com"
        assert results["scan_type"] == "tcp"
        assert len(results["hosts"]) == 1
        host = results["hosts"][0]
        assert host["ip"] == "127.0.0.1"
        ports = {p["port"]: p for p in host["ports"]}
        assert ports[80]["status"] == "open"
        assert ports[80]["service"] == "http"
        assert 81 not in ports  # closed ports are omitted

    def test_run_scan_no_open_ports(self):
        resolve = mock.patch("portscanner.scanner.resolve",
                             return_value="127.0.0.1")
        connect = mock.patch("portscanner.tcp_scan.tcp_connect_scan",
                             return_value=False)
        with resolve, connect:
            results = scanner.run_scan("example.com", [81],
                                       scan_types=("tcp",), threads=2)
        assert results["hosts"][0]["ports"] == []
