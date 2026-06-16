from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


ETHERTYPE_IPV4 = 0x0800
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17


@dataclass(frozen=True)
class PacketObservation:
    timestamp: datetime
    src_ip: str
    dest_ip: str
    src_port: int | None
    dest_port: int | None
    protocol: str
    length: int


def parse_ethernet_frame(data: bytes, *, timestamp: datetime | None = None) -> PacketObservation | None:
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None
    return parse_ipv4_packet(data[14:], timestamp=timestamp, frame_length=len(data))


def parse_ipv4_packet(
    data: bytes,
    *,
    timestamp: datetime | None = None,
    frame_length: int | None = None,
) -> PacketObservation | None:
    if len(data) < 20:
        return None
    first = data[0]
    version = first >> 4
    ihl = (first & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return None
    protocol_id = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dest_ip = socket.inet_ntoa(data[16:20])
    src_port: int | None = None
    dest_port: int | None = None
    protocol = _protocol_name(protocol_id)
    if protocol_id in {IPPROTO_TCP, IPPROTO_UDP} and len(data) >= ihl + 4:
        src_port, dest_port = struct.unpack("!HH", data[ihl : ihl + 4])
    length = frame_length if frame_length is not None else int(struct.unpack("!H", data[2:4])[0])
    return PacketObservation(
        timestamp=timestamp or datetime.now(tz=timezone.utc),
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        protocol=protocol,
        length=length,
    )


def iter_pcap(path: str | Path) -> Iterator[PacketObservation]:
    with Path(path).open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise ValueError("pcap file is too short")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("unsupported pcap magic")
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("truncated pcap packet header")
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            payload = handle.read(incl_len)
            if len(payload) != incl_len:
                raise ValueError("truncated pcap packet payload")
            timestamp = datetime.fromtimestamp(ts_sec + (ts_frac / 1_000_000), tz=timezone.utc)
            packet = parse_ethernet_frame(payload, timestamp=timestamp)
            if packet is not None:
                yield packet


def iter_interface(interface: str, *, limit: int | None = None) -> Iterator[PacketObservation]:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    count = 0
    try:
        while limit is None or count < limit:
            data = sock.recv(65535)
            timestamp = datetime.fromtimestamp(time.time(), tz=timezone.utc)
            packet = parse_ethernet_frame(data, timestamp=timestamp)
            if packet is None:
                continue
            count += 1
            yield packet
    finally:
        sock.close()


def _protocol_name(protocol_id: int) -> str:
    if protocol_id == IPPROTO_TCP:
        return "tcp"
    if protocol_id == IPPROTO_UDP:
        return "udp"
    if protocol_id == IPPROTO_ICMP:
        return "icmp"
    return f"ip-{protocol_id}"
