# -*- coding: utf-8 -*-
"""Read a pcap file *while tcpdump is still writing it* (tcpdump -U = packet-buffered).

No scapy: a small parser for classic pcap (not pcapng) with Ethernet / Linux-cooked link types and
IPv4 TCP/UDP/ICMP. A record that is only partly written is left for the next `read()` call, so the
reader never sees a torn packet. Lengths come from the IP header (wire size), so a short snaplen
(`-s 160`) does not shrink byte counts.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Optional

from src.features.flow_extractor import Packet

MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
         b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
LINK_ETHERNET, LINK_LINUX_SLL, LINK_RAW = 1, 113, 101
MAX_RECORD = 262_144  # anything bigger is a corrupt header, not a packet


class PcapFormatError(ValueError):
    pass


def parse_frame(ts: float, data: bytes, linktype: int) -> Optional[Packet]:
    """One captured frame -> Packet (IPv4 only), or None if it is not IPv4 TCP/UDP/ICMP-ish."""
    if linktype == LINK_ETHERNET:
        if len(data) < 14:
            return None
        off, etype = 14, struct.unpack_from("!H", data, 12)[0]
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:  # VLAN tags
            etype = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
    elif linktype == LINK_LINUX_SLL:
        if len(data) < 16:
            return None
        off, etype = 16, struct.unpack_from("!H", data, 14)[0]
    elif linktype == LINK_RAW:
        off, etype = 0, 0x0800
    else:
        return None
    if etype != 0x0800 or len(data) < off + 20:
        return None
    vihl = data[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    total_len = struct.unpack_from("!H", data, off + 2)[0]
    proto = data[off + 9]
    src = ".".join(str(b) for b in data[off + 12:off + 16])
    dst = ".".join(str(b) for b in data[off + 16:off + 20])
    t = off + ihl
    sport = dport = flags = window = 0
    hdr = ihl
    if proto == 6 and len(data) >= t + 14:
        sport, dport = struct.unpack_from("!HH", data, t)
        thl = (data[t + 12] >> 4) * 4
        flags = data[t + 13]
        window = struct.unpack_from("!H", data, t + 14)[0] if len(data) >= t + 16 else 0
        hdr += thl
    elif proto == 17 and len(data) >= t + 4:
        sport, dport = struct.unpack_from("!HH", data, t)
        hdr += 8
    elif proto == 1:
        hdr += 8
    payload = max(0, total_len - hdr)
    return Packet(timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=proto,
                  payload_len=payload, header_len=hdr, tcp_flags=flags, tcp_window=window)


class PcapTail:
    """Incremental reader. `read()` returns the packets that are completely on disk so far."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.offset = 0
        self.endian: Optional[str] = None
        self.tick = 1e-6
        self.linktype = LINK_ETHERNET
        self.packets_read = 0
        self.wire_bytes = 0

    def _header(self, fh) -> bool:
        raw = fh.read(24)
        if len(raw) < 24:
            return False
        if raw[:4] not in MAGIC:
            raise PcapFormatError(f"{self.path.name}: not a classic pcap (pcapng is not supported)")
        self.endian, self.tick = MAGIC[raw[:4]]
        self.linktype = struct.unpack(self.endian + "I", raw[20:24])[0]
        self.offset = 24
        return True

    def read(self, max_packets: int = 100_000) -> List[Packet]:
        out: List[Packet] = []
        try:
            fh = self.path.open("rb")
        except FileNotFoundError:
            return out
        with fh:
            if self.endian is None and not self._header(fh):
                return out
            fh.seek(self.offset)
            while len(out) < max_packets:
                rec = fh.read(16)
                if len(rec) < 16:
                    break  # header not fully written yet
                sec, frac, incl, orig = struct.unpack(self.endian + "IIII", rec)
                if incl > MAX_RECORD:
                    raise PcapFormatError(f"{self.path.name}: corrupt record at byte {self.offset}")
                data = fh.read(incl)
                if len(data) < incl:
                    break  # body not fully written yet: retry from this record next time
                self.offset += 16 + incl
                self.packets_read += 1
                pkt = parse_frame(sec + frac * self.tick, data, self.linktype)
                if pkt is not None:
                    self.wire_bytes += pkt.header_len + pkt.payload_len
                    out.append(pkt)
        return out
