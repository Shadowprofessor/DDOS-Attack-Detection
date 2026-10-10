# -*- coding: utf-8 -*-
"""
Libpcap Capture Backend — Default packet capture implementation.

Supports:
  - Live network interface sniffing via libpcap / Scapy
  - Offline PCAP / PCAPNG packet stream ingestion (streaming or batch)
  - In-memory packet list feeds for testing and pipeline integration

Completeness:
  - 100% (77/77 CICFlowMeter features measurable from raw packet headers/payloads).
"""
import os
from typing import Iterator, Iterable, List, Optional
from src.features.capture_backends.base import CaptureBackend
from src.features.flow_extractor import Packet


class LibpcapBackend(CaptureBackend):
    """Packet capture backend using libpcap / scapy for live or offline traffic.

    Args:
        pcap_path: Optional path to an offline .pcap or .pcapng file.
        packet_list: Optional in-memory iterable of ``Packet`` instances (useful for testing).
        interface: Optional network interface name for live sniffing (e.g. 'eth0').
        bpf_filter: Optional Berkeley Packet Filter string (e.g. 'tcp or udp').
        count: Maximum number of packets to capture (0 = unbounded).
    """

    def __init__(
        self,
        pcap_path: Optional[str] = None,
        packet_list: Optional[Iterable[Packet]] = None,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        count: int = 0,
    ):
        super().__init__()
        self.pcap_path = pcap_path
        self.packet_list = list(packet_list) if packet_list is not None else None
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count

    @property
    def backend_type(self) -> str:
        return "libpcap"

    @property
    def feature_completeness(self) -> float:
        return 1.0  # 77/77 features natively measurable

    def start(self) -> None:
        if self.pcap_path and not os.path.isfile(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
        self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def stream_packets(self) -> Iterator[Packet]:
        """Stream parsed ``Packet`` instances."""
        if not self._is_running:
            self.start()

        # Mode 1: In-memory packet list
        if self.packet_list is not None:
            for i, pkt in enumerate(self.packet_list):
                if not self._is_running:
                    break
                if self.count > 0 and i >= self.count:
                    break
                yield pkt
            return

        # Mode 2: Offline PCAP file
        if self.pcap_path is not None:
            try:
                from scapy.all import PcapReader, IP, TCP, UDP  # type: ignore
            except ImportError as exc:
                raise ImportError(
                    "scapy is required for PCAP reading in LibpcapBackend. Install via pip install scapy"
                ) from exc

            packet_idx = 0
            with PcapReader(self.pcap_path) as pcap_reader:
                for raw_pkt in pcap_reader:
                    if not self._is_running:
                        break
                    if self.count > 0 and packet_idx >= self.count:
                        break

                    if not raw_pkt.haslayer(IP):
                        continue

                    ip = raw_pkt[IP]
                    protocol = ip.proto
                    payload_len = len(ip.payload.payload) if ip.payload else 0
                    header_len = ip.ihl * 4

                    src_port = dst_port = 0
                    tcp_flags = 0
                    tcp_window = 0

                    if raw_pkt.haslayer(TCP):
                        tcp = raw_pkt[TCP]
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        tcp_flags = int(tcp.flags)
                        tcp_window = tcp.window
                        header_len += tcp.dataofs * 4
                        payload_len = max(0, len(tcp.payload))
                    elif raw_pkt.haslayer(UDP):
                        udp = raw_pkt[UDP]
                        src_port = udp.sport
                        dst_port = udp.dport
                        header_len += 8
                        payload_len = max(0, len(udp.payload))

                    pkt = Packet(
                        timestamp=float(raw_pkt.time),
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        payload_len=payload_len,
                        header_len=header_len,
                        tcp_flags=tcp_flags,
                        tcp_window=tcp_window,
                    )
                    packet_idx += 1
                    yield pkt
            return

        # Mode 3: Live NIC capture via scapy sniff
        if self.interface is not None:
            try:
                from scapy.all import sniff, IP, TCP, UDP  # type: ignore
            except ImportError as exc:
                raise ImportError(
                    "scapy is required for live sniffing in LibpcapBackend. Install via pip install scapy"
                ) from exc

            sniff_kwargs = {
                "iface": self.interface,
                "count": self.count if self.count > 0 else 0,
                "store": False,
            }
            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter

            packet_queue: List[Packet] = []

            def _pkt_callback(raw_pkt):
                if not raw_pkt.haslayer(IP):
                    return
                ip = raw_pkt[IP]
                protocol = ip.proto
                payload_len = len(ip.payload.payload) if ip.payload else 0
                header_len = ip.ihl * 4
                src_port = dst_port = tcp_flags = tcp_window = 0

                if raw_pkt.haslayer(TCP):
                    tcp = raw_pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_flags = int(tcp.flags)
                    tcp_window = tcp.window
                    header_len += tcp.dataofs * 4
                    payload_len = max(0, len(tcp.payload))
                elif raw_pkt.haslayer(UDP):
                    udp = raw_pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    header_len += 8
                    payload_len = max(0, len(udp.payload))

                pkt = Packet(
                    timestamp=float(raw_pkt.time),
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    payload_len=payload_len,
                    header_len=header_len,
                    tcp_flags=tcp_flags,
                    tcp_window=tcp_window,
                )
                packet_queue.append(pkt)

            sniff_kwargs["prn"] = _pkt_callback
            sniff(**sniff_kwargs)

            for pkt in packet_queue:
                yield pkt
            return

        # Fallback if no source configured
        return
