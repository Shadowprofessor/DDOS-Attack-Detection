# -*- coding: utf-8 -*-
"""
Base Capture Backend Interface — Layer 1 Pluggable Network Capture.

Defines the common abstract interface for all network traffic capture sources:
  - LibpcapBackend: Live NIC or offline PCAP packet capture (100% feature completeness)
  - CloudFlowLogBackend: Cloud provider flow logs (AWS, Azure, GCP) (~14% completeness)
  - EbpfBackend: Kernel-bypass eBPF capture stub (Phase 4 roadmap)
"""
import abc
from typing import Iterator, Optional
from src.features.flow_extractor import Packet


class CaptureBackend(abc.ABC):
    """Abstract base class for all packet and flow capture backends.

    Subclasses must implement:
      - ``start()``: Initialize and open the capture resource.
      - ``stop()``: Close the capture resource and release buffers.
      - ``stream_packets()``: Generator yielding ``Packet`` instances.

    Properties:
      - ``backend_type``: Machine-readable identifier string (e.g. 'libpcap', 'cloud_flow_log').
      - ``feature_completeness``: Float in [0.0, 1.0] indicating the proportion of
        CICFlowMeter 77 features natively measurable by this backend.
    """

    def __init__(self):
        self._is_running: bool = False

    @property
    @abc.abstractmethod
    def backend_type(self) -> str:
        """Identifier of the capture backend mechanism."""
        pass

    @property
    @abc.abstractmethod
    def feature_completeness(self) -> float:
        """Fraction of the 77 CICFlowMeter features measurable by this backend.

        Full-packet capture backends (libpcap, eBPF) yield 1.0 (77/77).
        Aggregated flow log backends (AWS/Azure/GCP) yield ~0.14 (~11/77) because
        per-packet IAT, window sizes, and flag variations are unavailable.
        """
        pass

    @property
    def is_running(self) -> bool:
        """Whether the capture source is actively running."""
        return self._is_running

    @abc.abstractmethod
    def start(self) -> None:
        """Initialize and open the capture backend."""
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """Gracefully stop packet capture and release resources."""
        pass

    @abc.abstractmethod
    def stream_packets(self) -> Iterator[Packet]:
        """Yield parsed ``Packet`` dataclass instances in arrival order.

        Yields:
            Packet: Standardized packet representation for FlowExtractor.
        """
        pass

    def __enter__(self) -> "CaptureBackend":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
