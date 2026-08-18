"""Export scan results to JSON and CSV."""

import csv
import json
import time


def to_json(results, path):
    payload = {
        "scan": {
            "target": results.get("target"),
            "started": results.get("started"),
            "finished": results.get("finished"),
            "duration_seconds": results.get("duration"),
            "scan_type": results.get("scan_type"),
        },
        "hosts": results.get("hosts", []),
    }
    with open(path, "w", encoding="utf-8", newline="") as fh:
        json.dump(payload, fh, indent=2)


def to_csv(results, path):
    fieldnames = [
        "host",
        "port",
        "protocol",
        "status",
        "service",
        "version",
    ]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for host in results.get("hosts", []):
            for port in host.get("ports", []):
                writer.writerow(
                    {
                        "host": host.get("host"),
                        "port": port.get("port"),
                        "protocol": port.get("protocol"),
                        "status": port.get("status"),
                        "service": port.get("service", ""),
                        "version": port.get("version", ""),
                    }
                )


def _iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())