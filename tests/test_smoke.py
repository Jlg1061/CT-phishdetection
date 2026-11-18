"""Smoke tests: the pipeline runs and produces sane metrics."""

import numpy as np
import pandas as pd

from src.data import load_data
from src.evaluate import compute_metrics
from src.train import (
    CLASSICAL_MODELS,
    build_classical_model,
    train_all_classical_models,
)

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


def test_build_classical_models():
    for name in (
        "logistic_regression",
        "random_forest",
        "svm",
        "decision_tree",
        "knn",
        "naive_bayes",
        "gradient_boosting",
    ):
        model = build_classical_model({"seed": 0, "model": {"type": name}})

        assert model is not None


def test_classical_models_ignore_custom_params():
    forest = build_classical_model(
        {
            "seed": 0,
            "model": {
                "type": "random_forest",
                "params": {"n_estimators": 200, "max_depth": 12},
            },
        }
    )

    assert forest.n_estimators == 100
    assert forest.max_depth is None


def test_classical_runs_all_models(tmp_path):
    cfg = {
        "seed": 0,
        "model": {"type": "classical"},
    }

    Xtr, Xte, ytr, yte = load_data(
        {
            "seed": 0,
            "data": {
                "source": "synthetic",
                "n_samples": 400,
                "n_features": 10,
                "test_size": 0.25,
            },
        }
    )

    all_metrics, best_model_name, best_metrics = train_all_classical_models(
        cfg, Xtr, Xte, ytr, yte, str(tmp_path)
    )

    assert set(all_metrics) == set(CLASSICAL_MODELS)
    assert best_model_name in CLASSICAL_MODELS
    assert isinstance(best_metrics, dict)
    assert set(best_metrics) >= {"accuracy", "precision", "recall", "f1", "roc_auc"}
    assert len(list(tmp_path.glob("confusion_matrix_*.png"))) == len(CLASSICAL_MODELS)
