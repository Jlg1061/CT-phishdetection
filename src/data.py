"""Data loading and preparation.

Replace `load_data` with your real security dataset (e.g., CIC-IoT2023, UNSW-NB15).
The synthetic default lets `make reproduce` run end-to-end out of the box.
"""

from __future__ import annotations

import pandas as pd
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


def load_data(cfg: dict):
    """Return (X_train, X_test, y_train, y_test) as float32 / int64 numpy arrays."""
    d = cfg["data"]
    if d["source"] == "synthetic":
        X, y = make_classification(
            n_samples=d["n_samples"],
            n_features=d["n_features"],
            n_informative=max(2, d["n_features"] // 2),
            n_classes=2,
            random_state=cfg["seed"],
        )
    else:
        # Real data path: a CSV with a `target` column.
        df = pd.read_csv(d["csv_path"])
        y = df[d["target"]].to_numpy()

        if y.dtype.kind in ["U", "S", "O"]:
            y = LabelEncoder().fit_transform(y)

        drop_columns = d.get("drop_columns", [])

        if isinstance(drop_columns, str):
            drop_columns = [drop_columns]

        X = (
            df.drop(columns=[d["target"], *drop_columns], errors="ignore")
            .select_dtypes("number")
            .to_numpy()
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=d["test_size"], random_state=cfg["seed"], stratify=y
    )
    # Scale using TRAIN statistics only (avoid data leakage — see L04/Unit I).
    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train).astype("float32")
    X_test = scaler.transform(X_test).astype("float32")
    return X_train, X_test, y_train.astype("int64"), y_test.astype("int64")
