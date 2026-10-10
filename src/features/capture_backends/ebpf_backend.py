# -*- coding: utf-8 -*-
"""
eBPF Capture Backend Stub — High-performance kernel-bypass packet ingestion.

Phase Roadmap:
  This backend is scheduled for implementation in Phase 4 (XDP / eBPF kernel-space
  packet parsing and ring-buffer streaming).
"""
from typing import Iterator
from src.features.capture_backends.base import CaptureBackend
from src.features.flow_extractor import Packet


class EbpfBackend(CaptureBackend):
    """Stub eBPF / XDP kernel-bypass capture backend for Phase 4.

    Any attempt to start or stream packets from this backend raises a
    descriptive ``NotImplementedError`` pointing to the Phase 4 roadmap.
    """

    @property
    def backend_type(self) -> str:
        return "ebpf"

    @property
    def feature_completeness(self) -> float:
        return 1.0  # Once implemented in Phase 4, full packets yield 77/77 features

    def start(self) -> None:
        raise NotImplementedError(
            "eBPF capture backend is scheduled for implementation in Phase 4 "
            "(high-throughput kernel-bypass packet capture using XDP/eBPF ring buffers). "
            "Please use LibpcapBackend (default) for current live or offline captures."
        )

    def stop(self) -> None:
        self._is_running = False

    def stream_packets(self) -> Iterator[Packet]:
        raise NotImplementedError(
            "eBPF capture backend is scheduled for implementation in Phase 4 "
            "(high-throughput kernel-bypass packet capture using XDP/eBPF ring buffers). "
            "Please use LibpcapBackend (default) for current live or offline captures."
        )
