from __future__ import annotations

import struct
from pathlib import Path

from civicbaseline.models import PcapFlow

# Well-known cleartext or weakly authenticated industrial / remote-admin ports.
# Detection is by destination port only — no payload decoding, no protocol exploits.
CLEARTEXT_PORTS = {
    21: "ftp",
    23: "telnet",
    80: "http",
    502: "modbus-tcp",
    102: "iec-s7comm",
    20000: "dnp3",
    2404: "iec-104",
    47808: "bacnet",
    161: "snmp",
}


def load_pcap_flows(path: Path, ip_zones: dict[str, str] | None = None) -> list[PcapFlow]:
    data = path.read_bytes()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return []
    little = magic == b"\xd4\xc3\xb2\xa1"
    endian = "<" if little else ">"
    offset = 24
    flows: list[PcapFlow] = []
    zones = ip_zones or {}
    while offset + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        packet = data[offset : offset + incl_len]
        offset += incl_len
        parsed = _parse_ethernet_ip(packet)
        if not parsed:
            continue
        src_ip, dst_ip, src_port, dst_port, proto = parsed
        cleartext = dst_port in CLEARTEXT_PORTS or src_port in CLEARTEXT_PORTS
        flows.append(
            PcapFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                cleartext=cleartext,
                src_zone=zones.get(src_ip) or _prefix_zone(src_ip, zones),
                dst_zone=zones.get(dst_ip) or _prefix_zone(dst_ip, zones),
            )
        )
    return flows


def _prefix_zone(ip: str, zones: dict[str, str]) -> str | None:
    if ip in zones:
        return zones[ip]
    # Allow CIDR-less prefix keys like "192.168.10."
    for key, zone in zones.items():
        if key.endswith(".") and ip.startswith(key):
            return zone
    return None


def _parse_ethernet_ip(packet: bytes) -> tuple[str, str, int | None, int | None, str] | None:
    if len(packet) < 34:
        return None
    ethertype = struct.unpack_from("!H", packet, 12)[0]
    if ethertype != 0x0800:
        return None
    ip = packet[14:]
    version_ihl = ip[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(ip) < ihl + 4:
        return None
    proto_num = ip[9]
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    rest = ip[ihl:]
    proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto_num, str(proto_num))
    src_port = dst_port = None
    if proto in {"tcp", "udp"} and len(rest) >= 4:
        src_port, dst_port = struct.unpack_from("!HH", rest, 0)
    return src_ip, dst_ip, src_port, dst_port, proto


def write_minimal_pcap(path: Path, packets: list[bytes]) -> None:
    """Write a tiny pcap (little-endian, Ethernet) for fixtures and tests."""
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray()
    for pkt in packets:
        body.extend(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
        body.extend(pkt)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + body)


def ethernet_ip_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    eth = b"\x00" * 12 + b"\x08\x00"
    sip = bytes(int(p) for p in src_ip.split("."))
    dip = bytes(int(p) for p in dst_ip.split("."))
    # IPv4 header: version/ihl, tos, length, id, flags, ttl, proto TCP, checksum, src, dst
    total = 20 + 20
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + sip + dip
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, 0x02, 8192, 0, 0)
    return eth + ip + tcp
