#!/usr/bin/env python3
"""Create tiny synthetic PCAPs for fixtures (cleartext + cross-zone examples)."""

from __future__ import annotations

from pathlib import Path

from civicbaseline.pcap import ethernet_ip_tcp, write_minimal_pcap

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    water = ROOT / "fixtures" / "water-plant" / "traffic.pcap"
    write_minimal_pcap(
        water,
        [
            ethernet_ip_tcp("192.168.20.5", "192.168.10.10", 49152, 23),
            ethernet_ip_tcp("192.168.20.5", "192.168.10.10", 49153, 80),
            ethernet_ip_tcp("203.0.113.9", "192.168.10.10", 44301, 502),
        ],
    )
    hospital = ROOT / "fixtures" / "hospital" / "traffic.pcap"
    write_minimal_pcap(
        hospital,
        [
            ethernet_ip_tcp("10.10.1.20", "10.50.1.8", 51500, 80),
        ],
    )
    substation = ROOT / "fixtures" / "substation" / "traffic.pcap"
    write_minimal_pcap(
        substation,
        [
            ethernet_ip_tcp("10.1.1.40", "10.80.1.12", 52000, 20000),
            ethernet_ip_tcp("198.51.100.8", "10.80.1.12", 44301, 80),
        ],
    )
    print(f"wrote {water}")
    print(f"wrote {hospital}")
    print(f"wrote {substation}")


if __name__ == "__main__":
    main()
