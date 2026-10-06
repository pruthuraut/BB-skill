#!/usr/bin/env python3
"""Normalize Nmap XML service evidence as tab-separated records."""

from __future__ import annotations

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


FIELDS = (
    "target",
    "address",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
)


def records(path: Path):
    root = ET.parse(path).getroot()
    for host in root.findall("host"):
        address_node = host.find("address")
        address = address_node.get("addr", "") if address_node is not None else ""
        hostname_node = host.find("./hostnames/hostname")
        target = hostname_node.get("name", "") if hostname_node is not None else ""
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            yield {
                "target": target or address,
                "address": address,
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", ""),
                "state": state.get("state", "") if state is not None else "",
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", nargs="*", type=Path)
    args = parser.parse_args()
    writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for path in args.xml:
        if not path.is_file():
            continue
        try:
            writer.writerows(records(path))
        except (ET.ParseError, OSError) as error:
            print(f"warning: could not parse {path}: {error}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
