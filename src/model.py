"""Model definition — a small PyTorch MLP (swap in your own architecture)."""

from __future__ import annotations

from torch import nn


class MLP(nn.Module):
    def __init__(
        self, in_features: int, hidden_sizes=(64, 32), n_classes=2, dropout=0.1
    ):
        super().__init__()
        layers, prev = [], in_features
        for h in hidden_sizes:
            layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        layers.append(nn.Linear(prev, n_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)
