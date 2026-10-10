# -*- coding: utf-8 -*-
"""
Tests for Step 0: Dataset Downloader & Synthetic Benchmark Generator.
"""
import os
import sys
import tempfile
import pandas as pd
import pytest

# Ensure Codes directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Codes")))

from ml.download_datasets import (
    check_kaggle_cli,
    generate_synthetic_benchmark,
    download_dataset,
    CICFLOWMETER_COLUMNS,
    CICDDOS2019_CLASSES,
)


class TestStep0_DatasetDownloader:
    """Tests for dataset downloading and synthetic benchmark generation."""

    def test_check_kaggle_cli(self):
        """Verify check_kaggle_cli runs cleanly and returns a boolean."""
        result = check_kaggle_cli()
        assert isinstance(result, bool)

    def test_generate_synthetic_benchmark(self):
        """Verify synthetic benchmark generator produces an 88-column CICFlowMeter dataset."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_csv = os.path.join(tmp_dir, "test_benchmark.csv")
            df = generate_synthetic_benchmark(tmp_csv, "cicddos2019", n_samples=500)

            assert os.path.exists(tmp_csv)
            assert len(df) == 500
            assert len(df.columns) == len(CICFLOWMETER_COLUMNS)
            assert list(df.columns) == CICFLOWMETER_COLUMNS
            assert "Label" in df.columns

            # Check that multi-class labels are present
            unique_labels = df["Label"].unique()
            assert len(unique_labels) > 1
            for lbl in unique_labels:
                assert lbl in CICDDOS2019_CLASSES

    def test_download_dataset_creates_dataset(self):
        """Verify download_dataset returns a valid existing file or directory containing dataset files."""
        path = download_dataset("cicddos2019")
        assert os.path.exists(path)

        if os.path.isdir(path):
            files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith('.csv') or f.endswith('.parquet')]
            assert len(files) > 0
        else:
            assert os.path.getsize(path) > 0
            if path.endswith('.csv'):
                df = pd.read_csv(path)
                assert len(df) > 0
