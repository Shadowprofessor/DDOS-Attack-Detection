# -*- coding: utf-8 -*-
"""
Tests for Pluggable Capture Backends (src/features/capture_backends/).

=============================================================================
FEATURE AUDIT DISCLOSURE: CLOUD FLOW LOG VS 77 CICFLOWMETER FEATURES
=============================================================================
Out of the 77 CICFLOWMETER_FEATURE_NAMES, with bidirectional forward+reverse
record pairing enabled within the sampling window, a cloud flow log backend
(AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs) natively populates:
  - 19 POPULATED FEATURES (~24.68% completeness):
      1.  Protocol
      2.  Flow Duration
      3.  Total Fwd Packets
      4.  Total Backward Packets (from paired reverse record)
      5.  Fwd Packets Length Total
      6.  Bwd Packets Length Total (from paired reverse record)
      7.  Flow Bytes/s
      8.  Flow Packets/s
      9.  Fwd Packets/s
      10. Bwd Packets/s
      11. Packet Length Mean
      12. Avg Packet Size
      13. Avg Fwd Segment Size
      14. Avg Bwd Segment Size
      15. Down/Up Ratio
      16. Subflow Fwd Packets
      17. Subflow Fwd Bytes
      18. Subflow Bwd Packets (from paired reverse record)
      19. Subflow Bwd Bytes (from paired reverse record)

  - 58 ZERO-FILLED / IMPUTED FEATURES (~75.32% deficit):
      Fwd Packet Length Min/Max/Std, Bwd Packet Length Min/Max/Mean/Std,
      Flow IAT Mean/Std/Max/Min, Fwd IAT Total/Mean/Std/Max/Min,
      Bwd IAT Total/Mean/Std/Max/Min, Fwd/Bwd PSH/URG Flags,
      Fwd/Bwd Header Length, Packet Length Min/Max/Std/Variance,
      FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Counts,
      Fwd/Bwd Bulk statistics (6 features),
      Init Fwd/Bwd Win Bytes, Fwd Act Data Packets, Fwd Seg Size Min,
      Active Mean/Std/Max/Min, Idle Mean/Std/Max/Min.

Flows derived from CloudFlowLogBackend are explicitly tagged with
`feature_completeness = 0.2468` and `backend_type = 'cloud_flow_log'`
so downstream systems can calibrate confidence for cloud-derived flows.
=============================================================================
"""
import json
import pytest
import numpy as np

from src.features.flow_extractor import (
    FlowExtractor,
    Flow,
    Packet,
    CICFLOWMETER_FEATURE_NAMES,
    NUM_FEATURES,
)
from src.features.capture_backends import (
    CaptureBackend,
    LibpcapBackend,
    CloudFlowLogBackend,
    EbpfBackend,
    CLOUD_FLOW_LOG_POPULATED_FEATURES,
    CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES,
    EBPF_HOST_INGRESS_POPULATED_FEATURES,
    EBPF_HOST_INGRESS_ZERO_FILLED_FEATURES,
    EBPF_TAP_POPULATED_FEATURES,
    EBPF_TAP_ZERO_FILLED_FEATURES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _create_sample_packets():
    """Create a deterministic packet sequence representing a bidirectional TCP exchange."""
    pkts = [
        # SYN from client
        Packet(timestamp=100.000, src_ip="192.168.1.10", dst_ip="10.0.0.1",
               src_port=49152, dst_port=80, protocol=6, payload_len=0,
               header_len=54, tcp_flags=0x02, tcp_window=65535),
        # SYN-ACK from server
        Packet(timestamp=100.010, src_ip="10.0.0.1", dst_ip="192.168.1.10",
               src_port=80, dst_port=49152, protocol=6, payload_len=0,
               header_len=54, tcp_flags=0x12, tcp_window=65535),
        # ACK from client
        Packet(timestamp=100.015, src_ip="192.168.1.10", dst_ip="10.0.0.1",
               src_port=49152, dst_port=80, protocol=6, payload_len=0,
               header_len=54, tcp_flags=0x10, tcp_window=65535),
        # HTTP GET request from client
        Packet(timestamp=100.020, src_ip="192.168.1.10", dst_ip="10.0.0.1",
               src_port=49152, dst_port=80, protocol=6, payload_len=350,
               header_len=54, tcp_flags=0x18, tcp_window=65535),
        # HTTP 200 Response from server
        Packet(timestamp=100.050, src_ip="10.0.0.1", dst_ip="192.168.1.10",
               src_port=80, dst_port=49152, protocol=6, payload_len=1400,
               header_len=54, tcp_flags=0x18, tcp_window=65535),
    ]
    return pkts


# ---------------------------------------------------------------------------
# Test 1: Feature Schema and Completeness Audit
# ---------------------------------------------------------------------------
class TestFeatureCompletenessAudit:
    """Verify feature partitions between full-packet and cloud-flow-log backends."""

    def test_schema_77_features_partition_exhaustive(self):
        """Audit that populated + zero_filled equals exactly the 77 CICFlowMeter features."""
        assert len(CICFLOWMETER_FEATURE_NAMES) == 77
        assert len(CLOUD_FLOW_LOG_POPULATED_FEATURES) == 19
        assert len(CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES) == 58
        assert len(CLOUD_FLOW_LOG_POPULATED_FEATURES) + len(CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES) == 77

        # Check disjointness
        overlap = set(CLOUD_FLOW_LOG_POPULATED_FEATURES).intersection(set(CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES))
        assert len(overlap) == 0, f"Unexpected overlap in feature partitions: {overlap}"

        # Check completeness covers all features in order
        all_features = set(CLOUD_FLOW_LOG_POPULATED_FEATURES).union(set(CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES))
        assert all_features == set(CICFLOWMETER_FEATURE_NAMES)

        all_ebpf_host = set(EBPF_HOST_INGRESS_POPULATED_FEATURES).union(set(EBPF_HOST_INGRESS_ZERO_FILLED_FEATURES))
        assert all_ebpf_host == set(CICFLOWMETER_FEATURE_NAMES)
        assert len(EBPF_HOST_INGRESS_POPULATED_FEATURES) == 54
        assert len(EBPF_HOST_INGRESS_ZERO_FILLED_FEATURES) == 23

    def test_backend_completeness_properties(self):
        """Check completeness ratios reported by backend instances."""
        pcap_backend = LibpcapBackend()
        assert pcap_backend.feature_completeness == 1.0
        assert pcap_backend.backend_type == "libpcap"

        cloud_backend = CloudFlowLogBackend()
        assert cloud_backend.feature_completeness == 0.2468
        assert cloud_backend.backend_type == "cloud_flow_log"

        # Host-ingress mode (default: 54/77 features, backward features unobserved without TC egress hook)
        ebpf_backend = EbpfBackend()
        assert ebpf_backend.feature_completeness == 0.7013
        assert ebpf_backend.backend_type == "ebpf"
        assert len(ebpf_backend.populated_features) == 54
        assert len(ebpf_backend.zero_filled_features) == 23

        # TAP/SPAN mode (inline mirror: both directions arrive at sensor NIC ingress)
        ebpf_tap = EbpfBackend(deployment_mode="tap")
        assert ebpf_tap.feature_completeness == 1.0
        assert len(ebpf_tap.populated_features) == 77


# ---------------------------------------------------------------------------
# Test 2: LibpcapBackend & Equivalence Test (Direct vs Backend Extraction)
# ---------------------------------------------------------------------------
class TestLibpcapBackendAndEquivalence:
    """Prove that LibpcapBackend and direct packet injection produce IDENTICAL 77-feature output."""

    def test_direct_vs_backend_77_feature_equivalence(self):
        """CRITICAL: FlowExtractor produces identical 77 features whether fed directly or via LibpcapBackend."""
        packets = _create_sample_packets()

        # Method A: Direct injection via process_packet + flush_all
        extractor_direct = FlowExtractor()
        flows_direct = []
        for pkt in packets:
            exp = extractor_direct.process_packet(pkt)
            if exp:
                flows_direct.append(exp)
        flows_direct.extend(extractor_direct.flush_all())

        assert len(flows_direct) == 1
        flow_a = flows_direct[0]
        vec_a = flow_a.to_feature_vector()
        assert len(vec_a) == 77

        # Method B: Pluggable backend via LibpcapBackend + extract_from_backend
        backend = LibpcapBackend(packet_list=packets)
        extractor_backend = FlowExtractor(backend=backend)
        flows_backend = extractor_backend.extract_from_backend()

        assert len(flows_backend) == 1
        flow_b = flows_backend[0]
        vec_b = flow_b.to_feature_vector()
        assert len(vec_b) == 77

        # Assert bit-for-bit / numeric equivalence across all 77 features
        for feat_name, val_a, val_b in zip(CICFLOWMETER_FEATURE_NAMES, vec_a, vec_b):
            assert val_a == pytest.approx(val_b, abs=1e-6), (
                f"Feature '{feat_name}' mismatch: direct={val_a} vs backend={val_b}"
            )

        np.testing.assert_allclose(vec_a, vec_b, rtol=1e-5, atol=1e-5)

        # Check metadata
        assert flow_b.backend_type == "libpcap"
        assert flow_b.feature_completeness == 1.0

    def test_libpcap_context_manager_lifecycle(self):
        """Test start, stop, and context manager lifecycle of LibpcapBackend."""
        packets = _create_sample_packets()[:2]
        backend = LibpcapBackend(packet_list=packets)

        assert not backend.is_running
        with backend as b:
            assert b.is_running
            streamed = list(b.stream_packets())
            assert len(streamed) == 2
        assert not backend.is_running

    def test_libpcap_missing_file_raises_error(self):
        """Test that a nonexistent PCAP path raises FileNotFoundError."""
        backend = LibpcapBackend(pcap_path="nonexistent_traffic_file.pcap")
        with pytest.raises(FileNotFoundError):
            backend.start()


# ---------------------------------------------------------------------------
# Test 3: CloudFlowLogBackend (AWS, Azure, GCP Formats & Degraded Tagging)
# ---------------------------------------------------------------------------
class TestCloudFlowLogBackend:
    """Test ingestion of cloud flow logs and verified completeness tagging."""

    def test_aws_vpc_flow_log_ingestion(self):
        """Test AWS VPC Flow Log record normalization and flow extraction."""
        aws_records = [
            {
                "version": 2,
                "account_id": "123456789012",
                "interface_id": "eni-0123456789abcdef0",
                "srcaddr": "172.31.1.50",
                "dstaddr": "172.31.2.100",
                "srcport": 54321,
                "dstport": 443,
                "protocol": 6,
                "packets": 50,
                "bytes": 25000,
                "start": 1609459200,
                "end": 1609459260,
                "action": "ACCEPT",
                "log_status": "OK",
            }
        ]

        backend = CloudFlowLogBackend(records=aws_records)
        extractor = FlowExtractor(backend=backend)
        flows = extractor.extract_from_backend()

        assert len(flows) == 1
        flow = flows[0]
        assert flow.backend_type == "cloud_flow_log"
        assert flow.feature_completeness == 0.2468
        assert flow.protocol == 6

        vec = flow.to_feature_vector()
        assert len(vec) == 77

        # Verify populated features have real values
        feat_dict = flow.to_feature_dict()
        assert feat_dict["Protocol"] == 6.0
        assert feat_dict["Flow Duration"] > 0
        assert feat_dict["Total Fwd Packets"] > 0
        assert feat_dict["Fwd Packets Length Total"] > 0
        assert feat_dict["Flow Bytes/s"] > 0

    def test_azure_nsg_flow_log_tuple_parsing(self):
        """Test Azure NSG Flow Log flowTuple string parsing."""
        # Azure NSG v1/v2 tuple: timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,trafficFlow,packets,bytes
        azure_data = {
            "records": [
                {
                    "properties": {
                        "flows": [
                            {
                                "flows": [
                                    {
                                        "flowTuples": [
                                            "1609459200,10.1.0.4,10.2.0.8,8080,443,T,I,A,25,12500"
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }

        backend = CloudFlowLogBackend(records=[azure_data])
        extractor = FlowExtractor(backend=backend)
        flows = extractor.extract_from_backend()

        assert len(flows) == 1
        flow = flows[0]
        assert flow.backend_type == "cloud_flow_log"
        assert flow.feature_completeness == 0.2468
        assert flow.protocol == 6
        assert len(flow.to_feature_vector()) == 77

    def test_gcp_vpc_flow_log_json_parsing(self):
        """Test GCP VPC Flow Log JSON structure parsing."""
        gcp_record = {
            "jsonPayload": {
                "connection": {
                    "src_ip": "10.128.0.2",
                    "dest_ip": "10.128.0.3",
                    "src_port": 35000,
                    "dest_port": 53,
                    "protocol": 17,
                },
                "packets": "10",
                "bytes": "800",
            },
            "timestamp_seconds": 1609459200.0,
        }

        backend = CloudFlowLogBackend(records=[gcp_record])
        extractor = FlowExtractor(backend=backend)
        flows = extractor.extract_from_backend()

        assert len(flows) == 1
        flow = flows[0]
        assert flow.backend_type == "cloud_flow_log"
        assert flow.feature_completeness == 0.2468
        assert flow.protocol == 17
        assert len(flow.to_feature_vector()) == 77

    def test_matched_forward_reverse_records_produce_single_bidirectional_flow(self):
        """CRITICAL: Test that matched forward and reverse records (swapped src/dst) produce exactly ONE Flow."""
        fwd_rec = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": 6,
            "packets": 15,
            "bytes": 3000,
            "start_time": 1000.0,
            "end_time": 1030.0,
        }
        rev_rec = {
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "src_port": 80,
            "dst_port": 12345,
            "protocol": 6,
            "packets": 12,
            "bytes": 18000,
            "start_time": 1001.0,
            "end_time": 1030.0,
        }

        backend = CloudFlowLogBackend(records=[fwd_rec, rev_rec], pairing_window=300.0)
        extractor = FlowExtractor(backend=backend)
        flows = extractor.extract_from_backend()

        # Must produce exactly ONE bidirectional flow, not two unidirectional flows
        assert len(flows) == 1
        flow = flows[0]
        assert flow.backend_type == "cloud_flow_log"
        assert flow.feature_completeness == 0.2468

        # Verify forward & backward split is populated from both directions
        assert flow.fwd_packet_count == 15
        assert flow.bwd_packet_count == 12
        assert flow.fwd_src_ip == "10.0.0.1"

        d = flow.to_feature_dict()
        assert d["Total Fwd Packets"] == 15.0
        assert d["Total Backward Packets"] == 12.0
        assert d["Subflow Bwd Packets"] == 12.0
        assert d["Subflow Bwd Bytes"] > 0
        assert d["Fwd Packets Length Total"] > 0
        assert d["Bwd Packets Length Total"] > 0
        assert d["Down/Up Ratio"] == pytest.approx(12.0 / 15.0)

        # Inter-arrival times must be non-negative due to chronological interleaving
        assert d["Flow IAT Min"] >= 0.0



# ---------------------------------------------------------------------------
# Test 4: EbpfBackend (Phase 4 Implementation & Graceful Fallback)
# ---------------------------------------------------------------------------
class TestEbpfBackendPhase4:
    """Test that EbpfBackend implementation in Phase 4 starts cleanly and falls back gracefully."""

    def test_ebpf_lifecycle_and_feature_completeness(self):
        backend = EbpfBackend()
        assert backend.backend_type == "ebpf"
        assert backend.feature_completeness == 0.7013

        tap_backend = EbpfBackend(deployment_mode="tap")
        assert tap_backend.feature_completeness == 1.0

        backend.start()
        assert backend.is_running is True
        backend.stop()
        assert backend.is_running is False

    def test_ebpf_stream_packets_with_packet_list(self):
        packets = _create_sample_packets()[:3]
        backend = EbpfBackend(packet_list=packets)
        backend.start()
        streamed = list(backend.stream_packets())
        assert len(streamed) == 3
        assert backend.backend_type == "ebpf"
        backend.stop()


# ---------------------------------------------------------------------------
# Test 5: Backward Compatibility of FlowExtractor
# ---------------------------------------------------------------------------
class TestFlowExtractorBackwardCompatibility:
    """Verify that existing FlowExtractor calling patterns remain completely intact."""

    def test_default_init_without_backend_works(self):
        """FlowExtractor() without backend argument still functions normally."""
        extractor = FlowExtractor(active_timeout=60.0, idle_timeout=30.0)
        assert extractor.backend is None
        assert extractor.active_timeout == 60.0

        pkt = Packet(
            timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=100, dst_port=200, protocol=6, payload_len=50
        )
        res = extractor.process_packet(pkt)
        assert res is None
        assert extractor.active_flow_count == 1

        flushed = extractor.flush_all()
        assert len(flushed) == 1
        # Default fallback is libpcap
        assert flushed[0].backend_type == "libpcap"
        assert flushed[0].feature_completeness == 1.0

    def test_extract_from_backend_without_backend_raises_value_error(self):
        extractor = FlowExtractor()
        with pytest.raises(ValueError) as exc_info:
            extractor.extract_from_backend()
        assert "No CaptureBackend provided" in str(exc_info.value)
