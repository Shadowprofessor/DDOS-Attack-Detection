# -*- coding: utf-8 -*-
"""Unit tests for the Layer 2 ML Model Pipeline & DDoSClassifier."""
import pytest
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import DDoSClassifier, CICDDOS2019_CLASSES, LABEL_NORMALIZATION


@pytest.fixture
def mock_trained_classifier():
    """Create a lightweight synthetic classifier for unit testing."""
    rng = np.random.RandomState(42)
    X = rng.randn(100, NUM_FEATURES)
    y = rng.choice(len(CICDDOS2019_CLASSES), size=100)

    imputer = SimpleImputer(strategy="median").fit(X)
    scaler = StandardScaler().fit(X)
    X_scaled = scaler.transform(imputer.transform(X))

    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(X_scaled, y)

    bundle = {
        "model": model,
        "scaler": scaler,
        "imputer": imputer,
        "classes": CICDDOS2019_CLASSES,
        "feature_names": CICFLOWMETER_FEATURE_NAMES,
    }
    return DDoSClassifier(bundle)


def test_classifier_predict_vector_list(mock_trained_classifier):
    """Test inference on a raw feature list."""
    clf = mock_trained_classifier
    vec = [0.0] * NUM_FEATURES
    vec[0] = 6.0  # TCP
    vec[1] = 1000.0  # duration

    result = clf.predict_vector(vec)
    assert "label" in result
    assert result["label"] in CICDDOS2019_CLASSES
    assert isinstance(result["is_attack"], bool)
    assert 0.0 <= result["confidence"] <= 1.0
    assert len(result["probabilities"]) == len(CICDDOS2019_CLASSES)
    assert pytest.approx(sum(result["probabilities"].values()), abs=1e-3) == 1.0


def test_classifier_predict_vector_dict(mock_trained_classifier):
    """Test inference on a feature dictionary."""
    clf = mock_trained_classifier
    feat_dict = {"Protocol": 17.0, "Flow Duration": 500000.0, "Total Fwd Packets": 10.0}

    result = clf.predict_vector(feat_dict)
    assert result["label"] in CICDDOS2019_CLASSES
    assert 0.0 <= result["confidence"] <= 1.0


def test_classifier_predict_batch(mock_trained_classifier):
    """Test batch inference with DataFrame and numpy array."""
    clf = mock_trained_classifier
    X_mat = np.random.randn(5, NUM_FEATURES)

    results = clf.predict_batch(X_mat)
    assert len(results) == 5
    for r in results:
        assert r["label"] in CICDDOS2019_CLASSES
        assert 0.0 <= r["confidence"] <= 1.0

    # Test with DataFrame
    df = pd.DataFrame(X_mat, columns=CICFLOWMETER_FEATURE_NAMES)
    results_df = clf.predict_batch(df)
    assert len(results_df) == 5


def test_classifier_handles_nan_and_inf(mock_trained_classifier):
    """Test that NaN and Inf values are safely handled without crashing."""
    clf = mock_trained_classifier
    vec = [0.0] * NUM_FEATURES
    vec[5] = float("inf")
    vec[10] = float("-inf")
    vec[15] = float("nan")

    result = clf.predict_vector(vec)
    assert result["label"] in CICDDOS2019_CLASSES
    assert not np.isnan(result["confidence"])


def test_classifier_invalid_feature_length(mock_trained_classifier):
    """Test that passing wrong feature count raises ValueError."""
    clf = mock_trained_classifier
    with pytest.raises(ValueError, match="Expected 77 features"):
        clf.predict_vector([1.0, 2.0, 3.0])


def test_taxonomy_and_normalization_map():
    """Verify taxonomy structure and label normalization mappings."""
    assert len(CICDDOS2019_CLASSES) == 13
    assert "Benign" in CICDDOS2019_CLASSES
    assert "TFTP" in CICDDOS2019_CLASSES
    assert "Portmap" in CICDDOS2019_CLASSES
    assert "SSDP" not in CICDDOS2019_CLASSES  # Verified dropped

    # Test all normalization mappings
    assert LABEL_NORMALIZATION["DrDoS_UDP"] == "UDP"
    assert LABEL_NORMALIZATION["DrDoS_MSSQL"] == "MSSQL"
    assert LABEL_NORMALIZATION["DrDoS_LDAP"] == "LDAP"
    assert LABEL_NORMALIZATION["DrDoS_NetBIOS"] == "NetBIOS"
    assert LABEL_NORMALIZATION["DrDoS_NTP"] == "NTP"
    assert LABEL_NORMALIZATION["DrDoS_DNS"] == "DNS"
    assert LABEL_NORMALIZATION["DrDoS_SNMP"] == "SNMP"
    assert LABEL_NORMALIZATION["UDP-lag"] == "UDP-Lag"
    assert LABEL_NORMALIZATION["UDPLag"] == "UDP-Lag"


def test_save_and_load_roundtrip(mock_trained_classifier, tmp_path):
    """Test model serialization and deserialization."""
    clf = mock_trained_classifier
    save_path = str(tmp_path / "model_bundle.pkl")
    clf.save(save_path)

    loaded_clf = DDoSClassifier(save_path)
    vec = [1.0] * NUM_FEATURES
    res1 = clf.predict_vector(vec)
    res2 = loaded_clf.predict_vector(vec)

    assert res1["label"] == res2["label"]
    assert pytest.approx(res1["confidence"]) == res2["confidence"]
