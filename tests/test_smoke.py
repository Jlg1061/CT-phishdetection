"""Smoke tests: the pipeline runs and produces sane metrics."""

import numpy as np
import pandas as pd

from src.data import load_data
from src.evaluate import compute_metrics

CFG = {
    "seed": 0,
    "data": {
        "source": "synthetic",
        "n_samples": 400,
        "n_features": 10,
        "test_size": 0.25,
    },
}


def test_load_data_shapes():
    Xtr, Xte, ytr, yte = load_data(CFG)
    assert Xtr.shape[1] == Xte.shape[1] == 10
    assert len(ytr) == 300 and len(yte) == 100


def test_metrics_range():
    y = np.array([0, 1, 0, 1])
    p = np.array([0.1, 0.9, 0.2, 0.8])
    m = compute_metrics(y, p)
    assert 0.0 <= m["roc_auc"] <= 1.0
    assert m["accuracy"] == 1.0


def test_csv_drop_columns(tmp_path):
    csv_path = tmp_path / "data.csv"
    pd.DataFrame(
        {
            "feature_keep": range(20),
            "feature_drop": range(20, 40),
            "label": [0, 1] * 10,
        }
    ).to_csv(csv_path, index=False)
    cfg = {
        "seed": 0,
        "data": {
            "source": "csv",
            "csv_path": str(csv_path),
            "target": "label",
            "drop_columns": ["feature_drop", "missing_column"],
            "test_size": 0.25,
        },
    }

    Xtr, Xte, ytr, yte = load_data(cfg)

    assert Xtr.shape[1] == Xte.shape[1] == 1
    assert len(ytr) == 15
    assert len(yte) == 5


def test_csv_encodes_string_labels(tmp_path):
    csv_path = tmp_path / "labels.csv"
    pd.DataFrame(
        {
            "feature": range(20),
            "label": ["benign", "malicious"] * 10,
        }
    ).to_csv(csv_path, index=False)
    cfg = {
        "seed": 0,
        "data": {
            "source": "csv",
            "csv_path": str(csv_path),
            "target": "label",
            "test_size": 0.25,
        },
    }

    _, _, ytr, yte = load_data(cfg)

    assert set(np.unique(np.concatenate([ytr, yte]))) <= {0, 1}
