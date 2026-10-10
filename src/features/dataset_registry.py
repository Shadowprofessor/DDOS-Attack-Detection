# -*- coding: utf-8 -*-
"""
Dataset Registry & Multi-Source Flow Normalization Module.

Provides normalized feature loading and label taxonomy mapping across:
  - CICDDoS2019 datasets
  - CICIoT2023 datasets
  - CAIDA DDoS traces (local files under research data-use agreements)
  - User-supplied PCAP files (via FlowExtractor)

All features are normalized into the exact 77-feature schema defined by
`CICFLOWMETER_FEATURE_NAMES` in `src.features.flow_extractor`.
"""

import os
import sys
import math
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Union, Generator, Any

from src.features.flow_extractor import (
    CICFLOWMETER_FEATURE_NAMES,
    NUM_FEATURES,
    FlowExtractor,
    Packet,
    Flow,
)
from src.models.classifier import (
    LABEL_NORMALIZATION as BASE_LABEL_NORMALIZATION,
    CICDDOS2019_CLASSES,
)

# ---------------------------------------------------------------------------
# Extended Label Taxonomy Normalization Map
# ---------------------------------------------------------------------------
LABEL_TAXONOMY_MAP: Dict[str, str] = {
    # Include base classifier mappings
    **BASE_LABEL_NORMALIZATION,
    # CICDDoS2019 variations
    "benign": "Benign",
    "BENIGN": "Benign",
    "drdos_dns": "DNS",
    "drdos_ntp": "NTP",
    "drdos_snmp": "SNMP",
    "drdos_mssql": "MSSQL",
    "drdos_udp": "UDP",
    "drdos_ldap": "LDAP",
    "drdos_netbios": "NetBIOS",
    "syn": "Syn",
    "udp-lag": "UDP-Lag",
    "udplag": "UDP-Lag",
    "tftp": "TFTP",
    "portmap": "Portmap",
    "webddos": "WebDDoS",
    # CICIoT2023 variations
    "benigntraffic": "Benign",
    "ddos-ack_flood": "UDP-Lag",
    "ddos-syn_flood": "Syn",
    "ddos-udp_flood": "UDP",
    "ddos-http_flood": "WebDDoS",
    "ddos-icmp_flood": "Other_DDoS",
    "ddos-rstfin_flood": "Other_DDoS",
    "ddos-pshack_flood": "Other_DDoS",
    "mirai-greeth_flood": "Other_DDoS",
    "mirai-udpplain": "UDP",
    "mirai-greip_flood": "Other_DDoS",
    # CAIDA / General variations
    "ddos": "Other_DDoS",
    "attack": "Other_DDoS",
    "normal": "Benign",
    "icmp_flood": "Other_DDoS",
    "syn_flood": "Syn",
    "udp_flood": "UDP",
}


def normalize_label(label: Any) -> str:
    """Normalize a raw attack/benign string label to canonical taxonomy.

    Args:
        label: Raw label string or numeric representation.

    Returns:
        Canonical taxonomy string (e.g. 'Benign', 'Syn', 'UDP', 'DNS').
    """
    if pd.isna(label) or label is None:
        return "Benign"
    s_label = str(label).strip()
    if not s_label:
        return "Benign"
    
    # Exact match check first
    if s_label in CICDDOS2019_CLASSES:
        return s_label
    
    # Case-insensitive / normalized map check
    lower_label = s_label.lower()
    if s_label in LABEL_TAXONOMY_MAP:
        return LABEL_TAXONOMY_MAP[s_label]
    if lower_label in LABEL_TAXONOMY_MAP:
        return LABEL_TAXONOMY_MAP[lower_label]

    # Partial keyword heuristic matching
    if "benign" in lower_label or "normal" in lower_label:
        return "Benign"
    if "syn" in lower_label:
        return "Syn"
    if "udp" in lower_label and "lag" in lower_label:
        return "UDP-Lag"
    if "udp" in lower_label:
        return "UDP"
    if "dns" in lower_label:
        return "DNS"
    if "ntp" in lower_label:
        return "NTP"
    if "mssql" in lower_label:
        return "MSSQL"
    if "ldap" in lower_label:
        return "LDAP"
    if "snmp" in lower_label:
        return "SNMP"
    if "netbios" in lower_label:
        return "NetBIOS"
    if "http" in lower_label or "web" in lower_label:
        return "WebDDoS"

    return "Other_DDoS"


def normalize_labels(label_series: pd.Series) -> pd.Series:
    """Vectorized label normalization for pandas Series."""
    return label_series.apply(normalize_label)


# ---------------------------------------------------------------------------
# Shared Schema Validation & Sanitization
# ---------------------------------------------------------------------------
def sanitize_numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    """Sanitize NaN and Inf numeric values in feature DataFrame (flow_extractor policy)."""
    df = df.copy()
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col in df.columns:
            s = pd.to_numeric(df[col], errors="coerce")
            s = s.replace([np.inf, -np.inf], np.nan)
            df[col] = s.fillna(0.0)
    return df


def validate_schema(data: Union[pd.DataFrame, dict, list], sanitize_nan: bool = True) -> pd.DataFrame:
    """Validate that input matches CICFLOWMETER_FEATURE_NAMES (77 numeric features).

    Args:
        data: Input DataFrame, dict, or list of feature dicts/vectors.
        sanitize_nan: If True, replaces NaN/Inf values with 0.0 defaults.

    Returns:
        Validated pd.DataFrame containing exact CICFLOWMETER_FEATURE_NAMES columns in order.

    Raises:
        ValueError: If input is empty, malformed, or missing required feature columns.
    """
    if data is None:
        raise ValueError("Input data cannot be None.")

    if isinstance(data, dict):
        df = pd.DataFrame([data])
    elif isinstance(data, list):
        if not data:
            raise ValueError("Input list is empty.")
        if isinstance(data[0], list):
            df = pd.DataFrame(data, columns=CICFLOWMETER_FEATURE_NAMES[:len(data[0])])
        else:
            df = pd.DataFrame(data)
    elif isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        raise ValueError(f"Unsupported data type for schema validation: {type(data)}")

    if df.empty:
        raise ValueError("Cannot validate empty dataset.")

    # Strip column names if string
    df.columns = [str(c).strip() for c in df.columns]

    # Deduplicate column names (keep first occurrence)
    if df.columns.duplicated().any():
        df = df.loc[:, ~df.columns.duplicated()].copy()

    # Check for missing feature columns
    missing = [col for col in CICFLOWMETER_FEATURE_NAMES if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns in schema: {missing[:5]} (total missing: {len(missing)})")

    # Select exact columns in standard order
    df = df[CICFLOWMETER_FEATURE_NAMES]

    # Type coercion & NaN sanitization
    if sanitize_nan:
        df = sanitize_numeric_features(df)
    else:
        # Coerce to numeric
        for col in CICFLOWMETER_FEATURE_NAMES:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


# ---------------------------------------------------------------------------
# Source Adapter: CICDDoS2019
# ---------------------------------------------------------------------------
CICDDOS2019_COLUMN_ALIAS_MAP: Dict[str, str] = {
    "Flow ID": "Flow ID",
    "Source IP": "Source IP",
    "Src IP": "Source IP",
    "Destination IP": "Destination IP",
    "Dst IP": "Destination IP",
    "Source Port": "Source Port",
    "Src Port": "Source Port",
    "Destination Port": "Destination Port",
    "Dst Port": "Destination Port",
    "Protocol": "Protocol",
    "Timestamp": "Timestamp",
    "Flow Duration": "Flow Duration",
    "Total Fwd Packets": "Total Fwd Packets",
    "Total Backward Packets": "Total Backward Packets",
    "Total Length of Fwd Packets": "Fwd Packets Length Total",
    "Fwd Packets Length Total": "Fwd Packets Length Total",
    "Total Length of Bwd Packets": "Bwd Packets Length Total",
    "Bwd Packets Length Total": "Bwd Packets Length Total",
    "Fwd Packet Length Max": "Fwd Packet Length Max",
    "Fwd Packet Length Min": "Fwd Packet Length Min",
    "Fwd Packet Length Mean": "Fwd Packet Length Mean",
    "Fwd Packet Length Std": "Fwd Packet Length Std",
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    "Bwd Packet Length Min": "Bwd Packet Length Min",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Std": "Bwd Packet Length Std",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Length": "Fwd Header Length",
    "Bwd Header Length": "Bwd Header Length",
    "Fwd Packets/s": "Fwd Packets/s",
    "Bwd Packets/s": "Bwd Packets/s",
    "Min Packet Length": "Packet Length Min",
    "Packet Length Min": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "Packet Length Max": "Packet Length Max",
    "Packet Length Mean": "Packet Length Mean",
    "Packet Length Std": "Packet Length Std",
    "Packet Length Variance": "Packet Length Variance",
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "PSH Flag Count": "PSH Flag Count",
    "ACK Flag Count": "ACK Flag Count",
    "URG Flag Count": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Count": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Avg Packet Size",
    "Avg Packet Size": "Avg Packet Size",
    "Avg Fwd Segment Size": "Avg Fwd Segment Size",
    "Avg Bwd Segment Size": "Avg Bwd Segment Size",
    "Fwd Header Length.1": "Fwd Header Length",
    "Fwd Avg Bytes/Bulk": "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk": "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate": "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk": "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk": "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate": "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "Init_Win_bytes_forward": "Init Fwd Win Bytes",
    "Init Fwd Win Bytes": "Init Fwd Win Bytes",
    "Init_Win_bytes_backward": "Init Bwd Win Bytes",
    "Init Bwd Win Bytes": "Init Bwd Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Packets",
    "Fwd Act Data Packets": "Fwd Act Data Packets",
    "min_seg_size_forward": "Fwd Seg Size Min",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label",
    "label": "Label",
}


def _process_cicddos2019_df(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Process and normalize a raw CICDDoS2019 DataFrame."""
    if raw_df is None or raw_df.empty:
        raise ValueError("Raw CICDDoS2019 dataset is empty or None.")

    raw_df = raw_df.copy()
    raw_df.columns = [str(c).strip() for c in raw_df.columns]

    # Map column names
    mapped_cols = {}
    for col in raw_df.columns:
        if col in CICDDOS2019_COLUMN_ALIAS_MAP:
            mapped_cols[col] = CICDDOS2019_COLUMN_ALIAS_MAP[col]

    raw_df = raw_df.rename(columns=mapped_cols)

    # Fill missing features with 0.0 defaults
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in raw_df.columns:
            raw_df[col] = 0.0

    # Normalize label if present
    label_col = None
    if "Label" in raw_df.columns:
        label_col = "Label"
    elif "label" in raw_df.columns:
        label_col = "label"

    labels = normalize_labels(raw_df[label_col]) if label_col else None

    # Validate feature schema
    validated_df = validate_schema(raw_df, sanitize_nan=True)

    if labels is not None:
        validated_df["Label"] = labels.values

    return validated_df


def load_cicddos2019(
    source: Union[str, pd.DataFrame, dict],
    chunksize: Optional[int] = None
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """Load and normalize CICDDoS2019 dataset from file path, DataFrame, or dict.

    Args:
        source: File path string, DataFrame, or dict.
        chunksize: If integer and source is file path, yields DataFrame chunks.

    Returns:
        Normalized pd.DataFrame or Generator yielding DataFrames.
    """
    if isinstance(source, (pd.DataFrame, dict)):
        df = source if isinstance(source, pd.DataFrame) else pd.DataFrame([source])
        return _process_cicddos2019_df(df)

    if not isinstance(source, str):
        raise TypeError(f"Invalid source type for load_cicddos2019: {type(source)}")

    if not os.path.isfile(source):
        raise FileNotFoundError(f"CICDDoS2019 source file not found: '{source}'")

    if chunksize is not None and chunksize > 0:
        def chunk_generator():
            for chunk in pd.read_csv(source, chunksize=chunksize, low_memory=False):
                yield _process_cicddos2019_df(chunk)
        return chunk_generator()
    else:
        df = pd.read_csv(source, low_memory=False)
        return _process_cicddos2019_df(df)


# ---------------------------------------------------------------------------
# Source Adapter: CICIoT2023
# ---------------------------------------------------------------------------
CICIOT2023_COLUMN_ALIAS_MAP: Dict[str, str] = {
    "flow_duration": "Flow Duration",
    "Header_Length": "Fwd Header Length",
    "Protocol Type": "Protocol",
    "protocol": "Protocol",
    "Protocol": "Protocol",
    "Duration": "Flow Duration",
    "Rate": "Flow Packets/s",
    "Srate": "Fwd Packets/s",
    "Drate": "Bwd Packets/s",
    "ack_count": "ACK Flag Count",
    "syn_count": "SYN Flag Count",
    "fin_count": "FIN Flag Count",
    "urg_count": "URG Flag Count",
    "rst_count": "RST Flag Count",
    "Tot sum": "Fwd Packets Length Total",
    "Min": "Packet Length Min",
    "Max": "Packet Length Max",
    "AVG": "Packet Length Mean",
    "Std": "Packet Length Std",
    "Tot size": "Avg Packet Size",
    "IAT": "Flow IAT Mean",
    "Number": "Total Fwd Packets",
    "Magnitue": "Packet Length Mean",
    "Radius": "Packet Length Std",
    "Variance": "Packet Length Variance",
    "Weight": "Total Fwd Packets",
    "label": "Label",
    "Label": "Label",
}


def _process_ciciot2023_df(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Process and normalize CICIoT2023 DataFrame to standard schema."""
    if raw_df is None or raw_df.empty:
        raise ValueError("Raw CICIoT2023 dataset is empty or None.")

    raw_df = raw_df.copy()
    raw_df.columns = [str(c).strip() for c in raw_df.columns]

    mapped_cols = {}
    for col in raw_df.columns:
        if col in CICIOT2023_COLUMN_ALIAS_MAP:
            mapped_cols[col] = CICIOT2023_COLUMN_ALIAS_MAP[col]

    raw_df = raw_df.rename(columns=mapped_cols)

    # Impute missing standard features
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in raw_df.columns:
            raw_df[col] = 0.0

    label_col = "Label" if "Label" in raw_df.columns else ("label" if "label" in raw_df.columns else None)
    labels = normalize_labels(raw_df[label_col]) if label_col else None

    validated_df = validate_schema(raw_df, sanitize_nan=True)

    if labels is not None:
        validated_df["Label"] = labels.values

    return validated_df


def load_ciciot2023(
    source: Union[str, pd.DataFrame, dict],
    chunksize: Optional[int] = None,
    nrows: Optional[int] = None,
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """Load and normalize CICIoT2023 dataset from file path, DataFrame, or dict.

    Args:
        source: File path string, DataFrame, or dict.
        chunksize: If integer and source is file path, yields DataFrame chunks.
        nrows: Optional max rows to read.

    Returns:
        Normalized pd.DataFrame or Generator yielding DataFrames.
    """
    if isinstance(source, (pd.DataFrame, dict)):
        df = source if isinstance(source, pd.DataFrame) else pd.DataFrame([source])
        return _process_ciciot2023_df(df)

    if not isinstance(source, str):
        raise TypeError(f"Invalid source type for load_ciciot2023: {type(source)}")

    if not os.path.isfile(source):
        raise FileNotFoundError(f"CICIoT2023 source file not found: '{source}'")

    if chunksize is not None and chunksize > 0:
        def chunk_generator():
            for chunk in pd.read_csv(source, chunksize=chunksize, nrows=nrows, low_memory=False):
                yield _process_ciciot2023_df(chunk)
        return chunk_generator()
    else:
        df = pd.read_csv(source, nrows=nrows, low_memory=False)
        return _process_ciciot2023_df(df)


# ---------------------------------------------------------------------------
# Source Adapter: CAIDA DDoS Traces
# ---------------------------------------------------------------------------
CAIDA_COLUMN_ALIAS_MAP: Dict[str, str] = {
    "proto": "Protocol",
    "protocol": "Protocol",
    "duration": "Flow Duration",
    "flow_duration": "Flow Duration",
    "pkts": "Total Fwd Packets",
    "packets": "Total Fwd Packets",
    "total_pkts": "Total Fwd Packets",
    "bytes": "Fwd Packets Length Total",
    "total_bytes": "Fwd Packets Length Total",
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "flags": "SYN Flag Count",
    "rate_pps": "Flow Packets/s",
    "rate_bps": "Flow Bytes/s",
    "label": "Label",
    "attack_type": "Label",
    "class": "Label",
}


def _process_caida_df(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Process and normalize CAIDA DDoS trace DataFrame to standard schema.

    NOTE: CAIDA DDoS traces are restricted research datasets provided under a
    researcher data-use agreement. CAIDA traces must be supplied via local
    filepaths or parsed record objects provided by the operator.
    """
    if raw_df is None or raw_df.empty:
        raise ValueError("Raw CAIDA dataset is empty or None.")

    raw_df = raw_df.copy()
    raw_df.columns = [str(c).strip() for c in raw_df.columns]

    mapped_cols = {}
    for col in raw_df.columns:
        if col in CAIDA_COLUMN_ALIAS_MAP:
            mapped_cols[col] = CAIDA_COLUMN_ALIAS_MAP[col]

    raw_df = raw_df.rename(columns=mapped_cols)

    # Default missing features to 0.0
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in raw_df.columns:
            raw_df[col] = 0.0

    label_col = "Label" if "Label" in raw_df.columns else None
    labels = normalize_labels(raw_df[label_col]) if label_col else None

    validated_df = validate_schema(raw_df, sanitize_nan=True)

    if labels is not None:
        validated_df["Label"] = labels.values

    return validated_df


def load_caida(
    source: Union[str, pd.DataFrame, dict],
    chunksize: Optional[int] = None
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """Load and normalize CAIDA DDoS trace dataset from local path, DataFrame, or dict.

    CAIDA DDoS traces are gated behind a researcher data-use agreement (not a
    public download). This adapter strictly accepts local file paths or pre-parsed
    trace records supplied by the operator, with no programmatic API fetch.

    Args:
        source: Local file path string, DataFrame, or dict.
        chunksize: If integer and source is file path, yields DataFrame chunks.

    Returns:
        Normalized pd.DataFrame or Generator yielding DataFrames.
    """
    if isinstance(source, (pd.DataFrame, dict)):
        df = source if isinstance(source, pd.DataFrame) else pd.DataFrame([source])
        return _process_caida_df(df)

    if not isinstance(source, str):
        raise TypeError(f"Invalid source type for load_caida: {type(source)}")

    if not os.path.isfile(source):
        raise FileNotFoundError(f"CAIDA local source file not found: '{source}'")

    if chunksize is not None and chunksize > 0:
        def chunk_generator():
            for chunk in pd.read_csv(source, chunksize=chunksize, low_memory=False):
                yield _process_caida_df(chunk)
        return chunk_generator()
    else:
        df = pd.read_csv(source, low_memory=False)
        return _process_caida_df(df)


# ---------------------------------------------------------------------------
# Source Adapter: Arbitrary PCAP Files (via FlowExtractor)
# ---------------------------------------------------------------------------
def load_pcap(
    source: Union[str, List[Packet]],
    active_timeout: float = 120.0,
    idle_timeout: float = 60.0,
    batch_size: Optional[int] = None
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """Extract flows from PCAP file or Packet list and normalize to feature schema.

    Args:
        source: Path to .pcap/.pcapng file or list of Packet dataclass instances.
        active_timeout: Seconds before active flow expiration.
        idle_timeout: Seconds of inactivity before idle flow expiration.
        batch_size: Optional chunk batch size yielding DataFrames for streaming.

    Returns:
        Normalized pd.DataFrame or Generator of DataFrames.
    """
    extractor = FlowExtractor(active_timeout=active_timeout, idle_timeout=idle_timeout)

    if isinstance(source, list):
        if not source:
            raise ValueError("Input packet list is empty.")
        if not isinstance(source[0], Packet):
            raise TypeError("List elements must be Packet instances.")
        completed_flows = []
        for pkt in source:
            expired = extractor.process_packet(pkt)
            if expired:
                completed_flows.append(expired)
        completed_flows.extend(extractor.flush_all())

        feature_dicts = [f.to_feature_dict() for f in completed_flows]
        if not feature_dicts:
            raise ValueError("No flows could be extracted from packet list.")
        df = pd.DataFrame(feature_dicts)
        return validate_schema(df, sanitize_nan=True)

    if not isinstance(source, str):
        raise TypeError(f"Invalid source type for load_pcap: {type(source)}")

    if not os.path.isfile(source):
        raise FileNotFoundError(f"PCAP source file not found: '{source}'")

    # Extract flows from PCAP via scapy/FlowExtractor
    flows = extractor.process_pcap(source)
    if not flows:
        raise ValueError(f"No valid flows extracted from PCAP file: '{source}'")

    feature_dicts = [f.to_feature_dict() for f in flows]
    df = pd.DataFrame(feature_dicts)

    if batch_size is not None and batch_size > 0:
        def pcap_chunk_generator():
            for i in range(0, len(df), batch_size):
                yield validate_schema(df.iloc[i : i + batch_size], sanitize_nan=True)
        return pcap_chunk_generator()

    return validate_schema(df, sanitize_nan=True)


# ---------------------------------------------------------------------------
# Source Adapter: InSDN Dataset
# ---------------------------------------------------------------------------
INSDN_COLUMN_ALIAS_MAP: Dict[str, str] = {
    "Protocol": "Protocol",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Fwd Packets Length Total",
    "TotLen Bwd Pkts": "Bwd Packets Length Total",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Packet Length Min",
    "Pkt Len Max": "Packet Length Max",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Avg Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init Fwd Win Bytes",
    "Init Bwd Win Byts": "Init Bwd Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label",
    "label": "Label",
}


def _process_insdn_df(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Process and normalize InSDN DataFrame to 77-feature schema."""
    if raw_df is None or raw_df.empty:
        raise ValueError("Raw InSDN dataset is empty or None.")

    raw_df = raw_df.copy()
    raw_df.columns = [str(c).strip() for c in raw_df.columns]

    mapped_cols = {}
    for col in raw_df.columns:
        if col in INSDN_COLUMN_ALIAS_MAP:
            mapped_cols[col] = INSDN_COLUMN_ALIAS_MAP[col]

    raw_df = raw_df.rename(columns=mapped_cols)

    # Impute missing standard features if any
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in raw_df.columns:
            raw_df[col] = 0.0

    label_col = "Label" if "Label" in raw_df.columns else ("label" if "label" in raw_df.columns else None)
    labels = normalize_labels(raw_df[label_col]) if label_col else None

    validated_df = validate_schema(raw_df, sanitize_nan=True)

    if labels is not None:
        validated_df["Label"] = labels.values

    return validated_df


def load_insdn(
    source: Union[str, pd.DataFrame, dict],
    chunksize: Optional[int] = None,
    nrows: Optional[int] = None,
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """Load and normalize InSDN dataset from file path, directory, DataFrame, or dict."""
    if isinstance(source, (pd.DataFrame, dict)):
        df = source if isinstance(source, pd.DataFrame) else pd.DataFrame([source])
        return _process_insdn_df(df)

    if not isinstance(source, str):
        raise TypeError(f"Invalid source type for load_insdn: {type(source)}")

    if os.path.isdir(source):
        dfs = []
        for fname in sorted(os.listdir(source)):
            if fname.endswith(".csv"):
                fpath = os.path.join(source, fname)
                sub_df = pd.read_csv(fpath, nrows=nrows, low_memory=False)
                dfs.append(_process_insdn_df(sub_df))
        if not dfs:
            raise FileNotFoundError(f"No CSV files found in InSDN directory: '{source}'")
        return pd.concat(dfs, ignore_index=True)

    if not os.path.isfile(source):
        raise FileNotFoundError(f"InSDN source file not found: '{source}'")

    if chunksize is not None and chunksize > 0:
        def chunk_generator():
            for chunk in pd.read_csv(source, chunksize=chunksize, nrows=nrows, low_memory=False):
                yield _process_insdn_df(chunk)
        return chunk_generator()
    else:
        df = pd.read_csv(source, nrows=nrows, low_memory=False)
        return _process_insdn_df(df)


# ---------------------------------------------------------------------------
# Source Adapter: Synthetic SDN (OpenFlow Table Stats)
# ---------------------------------------------------------------------------
SYNTHETIC_SDN_COLUMN_ALIAS_MAP: Dict[str, str] = {
    "ip_proto": "Protocol",
    "flow_duration_sec": "Flow Duration",
    "packet_count": "Total Fwd Packets",
    "byte_count": "Fwd Packets Length Total",
    "packet_count_per_second": "Flow Packets/s",
    "byte_count_per_second": "Flow Bytes/s",
    "label": "Label",
    "Label": "Label",
}


def _process_synthetic_sdn_df(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Process and normalize synthetic OpenFlow statistics DataFrame.
    
    NOTE: OpenFlow flow stats contain only 6 statistical counter features.
    The remaining 71 packet-level features are absent and filled with 0.0.
    """
    if raw_df is None or raw_df.empty:
        raise ValueError("Raw Synthetic SDN dataset is empty or None.")

    raw_df = raw_df.copy()
    raw_df.columns = [str(c).strip() for c in raw_df.columns]

    mapped_cols = {}
    for col in raw_df.columns:
        if col in SYNTHETIC_SDN_COLUMN_ALIAS_MAP:
            mapped_cols[col] = SYNTHETIC_SDN_COLUMN_ALIAS_MAP[col]

    raw_df = raw_df.rename(columns=mapped_cols)

    # Convert flow_duration_sec to microseconds if flow_duration_sec present
    if "Flow Duration" in raw_df.columns and "flow_duration_nsec" in raw_df.columns:
        raw_df["Flow Duration"] = (
            raw_df["Flow Duration"] * 1e6 + raw_df["flow_duration_nsec"] / 1e3
        )

    # Impute remaining 71 features as 0.0
    for col in CICFLOWMETER_FEATURE_NAMES:
        if col not in raw_df.columns:
            raw_df[col] = 0.0

    label_col = "Label" if "Label" in raw_df.columns else ("label" if "label" in raw_df.columns else None)
    labels = normalize_labels(raw_df[label_col]) if label_col else None

    validated_df = validate_schema(raw_df, sanitize_nan=True)

    if labels is not None:
        validated_df["Label"] = labels.values

    return validated_df


def load_synthetic_sdn(
    source: Union[str, pd.DataFrame, dict]
) -> pd.DataFrame:
    """Load synthetic OpenFlow switch statistics (e.g. FlowStatsfile.csv)."""
    if isinstance(source, (pd.DataFrame, dict)):
        df = source if isinstance(source, pd.DataFrame) else pd.DataFrame([source])
        return _process_synthetic_sdn_df(df)

    if not isinstance(source, str):
        raise TypeError(f"Invalid source type for load_synthetic_sdn: {type(source)}")

    if not os.path.isfile(source):
        raise FileNotFoundError(f"Synthetic SDN file not found: '{source}'")

    df = pd.read_csv(source, low_memory=False)
    return _process_synthetic_sdn_df(df)


# ---------------------------------------------------------------------------
# Unified Entry Point: load_dataset
# ---------------------------------------------------------------------------
def load_dataset(
    source_type: str,
    source: Any,
    **kwargs
) -> Union[pd.DataFrame, Generator[pd.DataFrame, None, None]]:
    """Unified dataset loader entry point.

    Dispatches source data to the specified adapter and returns a schema-validated
    DataFrame (or chunk generator).

    Args:
        source_type: One of ['cicddos2019', 'ciciot2023', 'caida', 'insdn', 'synthetic_sdn', 'pcap'].
        source: Filepath, DataFrame, dict, or packet list.
        **kwargs: Adapter-specific parameters (e.g. chunksize, active_timeout).

    Returns:
        Validated pd.DataFrame or Generator of DataFrames.

    Raises:
        ValueError: If source_type is unknown or validation fails.
    """
    if not source_type or not isinstance(source_type, str):
        raise ValueError("source_type must be a non-empty string.")

    stype = source_type.strip().lower()

    if stype == "cicddos2019":
        return load_cicddos2019(source, **kwargs)
    elif stype == "ciciot2023":
        return load_ciciot2023(source, **kwargs)
    elif stype == "caida":
        return load_caida(source, **kwargs)
    elif stype == "insdn":
        return load_insdn(source, **kwargs)
    elif stype == "synthetic_sdn":
        return load_synthetic_sdn(source, **kwargs)
    elif stype == "pcap":
        return load_pcap(source, **kwargs)
    else:
        raise ValueError(
            f"Unknown source_type '{source_type}'. Expected one of "
            f"['cicddos2019', 'ciciot2023', 'caida', 'insdn', 'synthetic_sdn', 'pcap']."
        )

