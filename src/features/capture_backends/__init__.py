# -*- coding: utf-8 -*-
"""
Pluggable Capture Backends — Layer 1 Network Capture Abstraction.
"""
from src.features.capture_backends.base import CaptureBackend
from src.features.capture_backends.libpcap_backend import LibpcapBackend
from src.features.capture_backends.cloud_flow_log_backend import (
    CloudFlowLogBackend,
    CLOUD_FLOW_LOG_POPULATED_FEATURES,
    CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES,
)
from src.features.capture_backends.ebpf_backend import (
    EbpfBackend,
    EBPF_POPULATED_FEATURES,
    EBPF_ZERO_FILLED_FEATURES,
)

__all__ = [
    "CaptureBackend",
    "LibpcapBackend",
    "CloudFlowLogBackend",
    "EbpfBackend",
    "CLOUD_FLOW_LOG_POPULATED_FEATURES",
    "CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES",
    "EBPF_POPULATED_FEATURES",
    "EBPF_ZERO_FILLED_FEATURES",
]
