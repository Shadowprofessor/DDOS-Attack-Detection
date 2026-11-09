#!/usr/bin/env python3
"""Check feature mapping for CICIoT2023 data."""
import sys
sys.path.insert(0, r'C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning')

from src.features.dataset_registry import load_ciciot2023
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES
import pandas as pd

# Load a few rows of real SYN flood data
df = load_ciciot2023(r'data\ciciot2023\DDoS-SYN_Flood.csv', nrows=5)

print(f"Shape: {df.shape}")
print(f"All columns: {list(df.columns)}")

# Check which CICFlowMeter features have non-zero values
for col in CICFLOWMETER_FEATURE_NAMES:
    if col in df.columns:
        non_zero = (df[col] != 0.0).sum()
        if non_zero > 0:
            print(f"  {col}: {non_zero}/5 non-zero, mean={df[col].mean():.2f}")

# Show what CICIoT2023 columns map to
print("\nCICIoT2023 column alias map coverage:")
from src.features.dataset_registry import CICIOT2023_COLUMN_ALIAS_MAP
mapped_to = set(CICIOT2023_COLUMN_ALIAS_MAP.values())
print(f"Mapped features: {len(mapped_to)} of {len(CICFLOWMETER_FEATURE_NAMES)}")
missing = set(CICFLOWMETER_FEATURE_NAMES) - mapped_to
print(f"Unmapped (defaulted to 0.0): {len(missing)}")