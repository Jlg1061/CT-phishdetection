"""Evaluation metrics and figures (see Unit I: evaluation validity)."""

from __future__ import annotations

import matplotlib
import numpy as np

matplotlib.use("Agg")  # headless: works in CI and on the cluster
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def compute_metrics(y_true, y_prob) -> dict:
    """y_prob = P(class 1). Report the metrics we emphasize in class."""
    y_pred = (y_prob >= 0.5).astype(int)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
    }


def save_confusion_matrix(y_true, y_prob, path):
    cm = confusion_matrix(y_true, (y_prob >= 0.5).astype(int))
    fig, ax = plt.subplots(figsize=(3.2, 3.2))
    ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, str(v), ha="center", va="center")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def save_roc_curve(y_true, y_prob, path):
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    ax.plot(fpr, tpr)
    ax.plot([0, 1], [0, 1], "--", color="gray")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
