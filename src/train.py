"""Single entry point: `python -m src.train --config config.yaml`.

Reproducibility standard: this command must recreate your reported results.
It writes results/metrics.json and figures to the output directory.
"""

from __future__ import annotations

import argparse
import json
import os
import random

import numpy as np
import torch
import yaml
from joblib import dump
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from torch import nn

from .data import load_data
from .evaluate import compute_metrics, save_confusion_matrix, save_roc_curve
from .model import MLP

CLASSICAL_MODELS = (
    "logistic_regression",
    "random_forest",
    "svm",
    "decision_tree",
    "knn",
    "naive_bayes",
    "gradient_boosting",
)


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def build_classical_model(cfg: dict):
    """Construct a configured scikit-learn classifier."""

    model = cfg["model"]["type"]
    seed = cfg["seed"]

    constructors = {
        "logistic_regression": lambda: LogisticRegression(random_state=seed),
        "random_forest": lambda: RandomForestClassifier(random_state=seed),
        "svm": lambda: SVC(random_state=seed),
        "decision_tree": lambda: DecisionTreeClassifier(random_state=seed),
        "knn": lambda: KNeighborsClassifier(),
        "naive_bayes": lambda: GaussianNB(),
        "gradient_boosting": lambda: GradientBoostingClassifier(random_state=seed),
    }

    if model not in constructors:
        raise ValueError(
            f"Unknown model type '{model}'. Choose mlp or one of: {', '.join(constructors)}"
        )

    return constructors[model]()


def classical_probability(model, X_test: np.ndarray) -> np.ndarray:
    """Return P(class 1), supporting classifiers with or without predict_proba."""

    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)

        if 1 in classes:
            return model.predict_proba(X_test)[:, classes.index(1)]

        return model.predict_proba(X_test)[:, -1]

    if hasattr(model, "decision_function"):
        scores = model.decision_function(X_test)

        scores = scores[:, 1] if getattr(scores, "ndim", 1) > 1 else scores
        scores = scores - np.min(scores)

        score_range = np.max(scores)

        return scores / score_range if score_range > 0 else np.full_like(scores, 0.5)

    return model.predict(X_test).astype("float64")


def train_custom_model(cfg: dict, X_tr, X_te, y_tr, y_te, device, out):
    Xtr = torch.tensor(X_tr, device=device)
    ytr = torch.tensor(y_tr, device=device)
    Xte = torch.tensor(X_te, device=device)

    model = MLP(
        X_tr.shape[1],
        tuple(cfg["model"]["hidden_sizes"]),
        dropout=cfg["model"]["dropout"],
    ).to(device)
    opt = torch.optim.Adam(
        model.parameters(),
        lr=cfg["train"]["lr"],
        weight_decay=cfg["train"]["weight_decay"],
    )
    loss_fn = nn.CrossEntropyLoss()
    bs = cfg["train"]["batch_size"]

    model.train()
    for epoch in range(cfg["train"]["epochs"]):
        perm = torch.randperm(Xtr.size(0))
        for i in range(0, Xtr.size(0), bs):
            idx = perm[i : i + bs]
            opt.zero_grad()
            loss = loss_fn(model(Xtr[idx]), ytr[idx])
            loss.backward()
            opt.step()

    model.eval()
    with torch.no_grad():
        prob = torch.softmax(model(Xte), dim=1)[:, 1].cpu().numpy()

    return prob


def train_classical_model(cfg: dict, X_tr, X_te, y_tr):
    model = build_classical_model(cfg)

    model.fit(X_tr, y_tr)

    prob = classical_probability(model, X_te)

    return prob


def train_all_classical_models(cfg: dict, X_tr, X_te, y_tr, y_te, out):
    """Train, evaluate, and save every supported classical classifier."""

    all_metrics: dict[str, dict] = {}

    best_model_name: str | None = None
    best_metrics: dict = {}
    best_prob = None

    for model_name in CLASSICAL_MODELS:
        model_cfg = {
            **cfg,
            "model": {**cfg["model"], "type": model_name},
        }

        prob = train_classical_model(model_cfg, X_tr, X_te, y_tr)
        metrics = compute_metrics(y_te, prob)

        all_metrics[model_name] = metrics

        save_confusion_matrix(
            y_te,
            prob,
            os.path.join(out, f"confusion_matrix_{model_name}.png"),
        )
        save_roc_curve(
            y_te,
            prob,
            os.path.join(out, f"roc_curve_{model_name}.png"),
        )

        if best_model_name is None or metrics["f1"] > best_metrics["f1"]:
            best_model_name = model_name
            best_metrics = metrics
            best_prob = prob

    save_confusion_matrix(y_te, best_prob, os.path.join(out, "confusion_matrix.png"))
    save_roc_curve(y_te, best_prob, os.path.join(out, "roc_curve.png"))

    return all_metrics, best_model_name, best_metrics


def main(config_path: str, model_override: str | None = None):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    set_seed(cfg["seed"])

    out = cfg["output"]["dir"]

    os.makedirs(out, exist_ok=True)

    X_tr, X_te, y_tr, y_te = load_data(cfg)

    if model_override:
        cfg["model"]["type"] = model_override

    model = cfg["model"]["type"]

    if model == "mlp":
        device = "cuda" if torch.cuda.is_available() else "cpu"

        prob = train_custom_model(cfg, X_tr, X_te, y_tr, y_te, device, out)
        metrics = compute_metrics(y_te, prob)

        save_confusion_matrix(y_te, prob, os.path.join(out, "confusion_matrix.png"))
        save_roc_curve(y_te, prob, os.path.join(out, "roc_curve.png"))
    elif model == "classical":
        all_metrics, best_model_name, metrics = train_all_classical_models(
            cfg, X_tr, X_te, y_tr, y_te, out
        )

        metrics = {
            **metrics,
            "models": all_metrics,
            "best_model": best_model_name,
        }
    else:
        prob = train_classical_model(cfg, X_tr, X_te, y_tr)
        metrics = compute_metrics(y_te, prob)

        save_confusion_matrix(y_te, prob, os.path.join(out, "confusion_matrix.png"))
        save_roc_curve(y_te, prob, os.path.join(out, "roc_curve.png"))

    with open(os.path.join(out, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("Results written to", out)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument(
        "--model",
        help="Override config model (mlp, logistic_regression, random_forest, svm, ...)",
    )
    args = ap.parse_args()
    main(args.config, args.model)
