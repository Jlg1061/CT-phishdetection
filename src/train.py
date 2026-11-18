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
from torch import nn

from .data import load_data
from .evaluate import compute_metrics, save_confusion_matrix, save_roc_curve
from .model import MLP


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def main(config_path: str):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    set_seed(cfg["seed"])
    out = cfg["output"]["dir"]
    os.makedirs(out, exist_ok=True)

    X_tr, X_te, y_tr, y_te = load_data(cfg)
    device = "cuda" if torch.cuda.is_available() else "cpu"

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

    metrics = compute_metrics(y_te, prob)
    with open(os.path.join(out, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    save_confusion_matrix(y_te, prob, os.path.join(out, "confusion_matrix.png"))
    save_roc_curve(y_te, prob, os.path.join(out, "roc_curve.png"))
    torch.save(model.state_dict(), os.path.join(out, "model.pt"))
    print("Results written to", out)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    main(ap.parse_args().config)
