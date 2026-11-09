#!/usr/bin/env python3
"""Test classifier with real CICIoT2023 data."""
import sys
sys.path.insert(0, r'C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning')

from src.features.dataset_registry import load_ciciot2023
from src.models.classifier import DDoSClassifier

# Load a few rows of real SYN flood data
df = load_ciciot2023(r'data\ciciot2023\DDoS-SYN_Flood.csv', nrows=5)
print(f'Loaded {len(df)} SYN flood flows')
print(f'Features: {list(df.columns)[:10]}...')
print(f'Labels: {df["Label"].unique()}')

# Load benign data
df_benign = load_ciciot2023(r'data\ciciot2023\BenignTraffic.csv', nrows=5)
print(f'Loaded {len(df_benign)} benign flows')
print(f'Labels: {df_benign["Label"].unique()}')

# Test classifier on real data
clf = DDoSClassifier(r'models\cicddos2019_rf.pkl')
for i in range(min(3, len(df))):
    row = df.iloc[i].to_dict()
    features = {k: v for k, v in row.items() if k != 'Label'}
    result = clf.predict_vector(features)
    print(f'Flow {i}: true_label=Syn, pred={result["label"]}, is_attack={result["is_attack"]}, conf={result["confidence"]:.3f}')

for i in range(min(2, len(df_benign))):
    row = df_benign.iloc[i].to_dict()
    features = {k: v for k, v in row.items() if k != 'Label'}
    result = clf.predict_vector(features)
    print(f'Benign {i}: true_label=Benign, pred={result["label"]}, is_attack={result["is_attack"]}, conf={result["confidence"]:.3f}')