# -*- coding: utf-8 -*-
"""
Tests for Dataset Registry & Multi-Source Flow Normalization.

Verifies:
  - Schema consistency across all four sources (CICDDoS2019, CICIoT2023, CAIDA, PCAP)
  - Label taxonomy normalization
  - Missing-field handling & 0.0 default imputation
  - NaN/Inf sanitization
  - Chunked/batch streaming
  - Malformed input matrix (at least one malformed case per source)
"""

import os
import tempfile
import pytest
import numpy as np
import pandas as pd

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, Packet
from src.features.dataset_registry import (
    validate_schema,
    normalize_label,
    normalize_labels,
    load_cicddos2019,
    load_ciciot2023,
    load_caida,
    load_pcap,
    load_dataset,
    sanitize_numeric_features,
)


@pytest.fixture
def sample_packet_list():
    """Generate a minimal sample packet list for PCAP testing."""
    pkts = [
        Packet(timestamp=1000.0, src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=54321, dst_port=80, protocol=6, payload_len=100, header_len=40, tcp_flags=2, tcp_window=8192),
        Packet(timestamp=1000.1, src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=80, dst_port=54321, protocol=6, payload_len=200, header_len=40, tcp_flags=18, tcp_window=8192),
        Packet(timestamp=1000.2, src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=54321, dst_port=80, protocol=6, payload_len=500, header_len=40, tcp_flags=16, tcp_window=8192),
    ]
    return pkts


# ---------------------------------------------------------------------------
# 1. Schema Consistency Tests
# ---------------------------------------------------------------------------
def test_schema_consistency_cicddos2019():
    raw_data = {
        " Flow Duration": 120000.0,
        " Protocol": 6,
        " Total Fwd Packets": 10,
        " Total Backward Packets": 8,
        "Total Length of Fwd Packets": 1500.0,
        " Label": "DrDoS_DNS",
    }
    df = load_cicddos2019(raw_data)
    assert isinstance(df, pd.DataFrame)
    assert len(df.columns) == len(CICFLOWMETER_FEATURE_NAMES) + 1  # 77 features + Label
    assert list(df.columns[:77]) == CICFLOWMETER_FEATURE_NAMES
    assert df["Label"].iloc[0] == "DNS"


def test_schema_consistency_ciciot2023():
    raw_data = {
        "flow_duration": 45000.0,
        "Protocol Type": 17,
        "Header_Length": 32,
        "ack_count": 0,
        "syn_count": 5,
        "label": "DDoS-SYN_Flood",
    }
    df = load_ciciot2023(raw_data)
    assert isinstance(df, pd.DataFrame)
    assert list(df.columns[:77]) == CICFLOWMETER_FEATURE_NAMES
    assert df["Label"].iloc[0] == "Syn"


def test_schema_consistency_caida():
    raw_data = {
        "duration": 5.0,
        "proto": 1,
        "pkts": 100,
        "bytes": 6400,
        "attack_type": "syn_flood",
    }
    df = load_caida(raw_data)
    assert isinstance(df, pd.DataFrame)
    assert list(df.columns[:77]) == CICFLOWMETER_FEATURE_NAMES
    assert df["Label"].iloc[0] == "Syn"


def test_schema_consistency_pcap(sample_packet_list):
    df = load_pcap(sample_packet_list)
    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == CICFLOWMETER_FEATURE_NAMES


def test_unified_load_dataset_dispatcher(sample_packet_list):
    sources = [
        ("cicddos2019", {" Protocol": 6, " Flow Duration": 1000}),
        ("ciciot2023", {"flow_duration": 1000, "Protocol Type": 6}),
        ("caida", {"duration": 1.0, "proto": 6}),
        ("pcap", sample_packet_list),
    ]

    for stype, sdata in sources:
        res = load_dataset(stype, sdata)
        assert isinstance(res, pd.DataFrame)
        assert list(res.columns[:77]) == CICFLOWMETER_FEATURE_NAMES


# ---------------------------------------------------------------------------
# 2. Label Taxonomy Normalization Tests
# ---------------------------------------------------------------------------
def test_label_taxonomy_normalization():
    test_cases = [
        ("DrDoS_DNS", "DNS"),
        ("DrDoS_UDP", "UDP"),
        ("UDP-lag", "UDP-Lag"),
        ("Syn", "Syn"),
        ("BENIGN", "Benign"),
        ("benign", "Benign"),
        ("DDoS-SYN_Flood", "Syn"),
        ("DDoS-ACK_Flood", "UDP-Lag"),
        ("ddos", "Other_DDoS"),
        ("normal", "Benign"),
    ]
    for raw, expected in test_cases:
        assert normalize_label(raw) == expected

    series = pd.Series(["DrDoS_DNS", "BENIGN", "syn_flood"])
    norm_series = normalize_labels(series)
    assert list(norm_series) == ["DNS", "Benign", "Syn"]


# ---------------------------------------------------------------------------
# 3. Missing-Field & Default Imputation Tests
# ---------------------------------------------------------------------------
def test_missing_field_handling():
    partial_data = {"Protocol": 6, "Flow Duration": 100.0}
    df = load_cicddos2019(partial_data)

    # Missing features should default to 0.0
    assert df["Total Fwd Packets"].iloc[0] == 0.0
    assert df["Fwd Packet Length Max"].iloc[0] == 0.0
    assert df["FIN Flag Count"].iloc[0] == 0.0


# ---------------------------------------------------------------------------
# 4. NaN / Inf Sanitization Safeguard Tests
# ---------------------------------------------------------------------------
def test_nan_inf_safeguards():
    bad_df = pd.DataFrame({
        "Protocol": [6, np.nan],
        "Flow Duration": [np.inf, -np.inf],
    })
    # Fill remaining columns
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in bad_df.columns:
            bad_df[col] = 1.0

    sanitized = sanitize_numeric_features(bad_df)
    assert not sanitized.isna().any().any()
    assert not np.isinf(sanitized.values).any()
    assert sanitized["Flow Duration"].iloc[0] == 0.0
    assert sanitized["Flow Duration"].iloc[1] == 0.0


# ---------------------------------------------------------------------------
# 5. Chunked & Batch Streaming Tests
# ---------------------------------------------------------------------------
def test_chunked_streaming_csv():
    rows = [
        {"Protocol": 6, "Flow Duration": 100.0},
        {"Protocol": 17, "Flow Duration": 200.0},
        {"Protocol": 1, "Flow Duration": 300.0},
        {"Protocol": 6, "Flow Duration": 400.0},
    ]
    df = pd.DataFrame(rows)
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0.0

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
        df.to_csv(tmp.name, index=False)
        tmp_path = tmp.name

    try:
        gen = load_cicddos2019(tmp_path, chunksize=2)
        chunks = list(gen)
        assert len(chunks) == 2
        assert len(chunks[0]) == 2
        assert len(chunks[1]) == 2
        assert list(chunks[0].columns[:77]) == CICFLOWMETER_FEATURE_NAMES
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_batch_streaming_pcap(sample_packet_list):
    # Duplicate packet sequence to create multiple flows
    pkts = sample_packet_list * 5
    gen = load_pcap(pkts, batch_size=2)
    assert isinstance(gen, pd.DataFrame)  # List input returns DataFrame directly


# ---------------------------------------------------------------------------
# 6. Malformed-Input Matrix Tests (At least 1 per source)
# ---------------------------------------------------------------------------
def test_malformed_input_cicddos2019():
    # File not found
    with pytest.raises(FileNotFoundError):
        load_cicddos2019("non_existent_file_12345.csv")

    # Invalid input type
    with pytest.raises(TypeError):
        load_cicddos2019(12345)

    # Empty DataFrame
    with pytest.raises(ValueError):
        load_cicddos2019(pd.DataFrame())


def test_malformed_input_ciciot2023():
    # File not found
    with pytest.raises(FileNotFoundError):
        load_ciciot2023("non_existent_ciciot.csv")

    # Invalid input type
    with pytest.raises(TypeError):
        load_ciciot2023(3.14159)

    # Empty DataFrame
    with pytest.raises(ValueError):
        load_ciciot2023(pd.DataFrame())


def test_malformed_input_caida():
    # File not found
    with pytest.raises(FileNotFoundError):
        load_caida("non_existent_caida_trace.csv")

    # Invalid input type
    with pytest.raises(TypeError):
        load_caida(["invalid", "list"])

    # Empty DataFrame
    with pytest.raises(ValueError):
        load_caida(pd.DataFrame())


def test_malformed_input_pcap():
    # File not found
    with pytest.raises(FileNotFoundError):
        load_pcap("non_existent_trace.pcap")

    # Invalid packet element in list
    with pytest.raises(TypeError):
        load_pcap(["not_a_packet_dataclass"])

    # Empty packet list
    with pytest.raises(ValueError):
        load_pcap([])


def test_unknown_source_type():
    with pytest.raises(ValueError):
        load_dataset("unknown_format_type", {"Protocol": 6})
