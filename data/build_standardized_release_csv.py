#!/usr/bin/env python3
"""Create a complete, self-contained CSV from a frozen split-safe cohort.

The CSV contains every retained model record exactly once and adds a stable
record identifier and chronological split label. It deliberately operates only
on the post-deduplication, post-leakage-purge Parquet cohort; per-certificate
raw temporal matches remain restricted intermediate artifacts.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


BASE_COLUMNS = (
    "hostname",
    "label",
    "collection_date",
    "ct_timestamp",
    "certificate_not_before",
    "certificate_not_after",
    "issuer",
    "san_count",
    "is_wildcard",
    "certificate_fingerprint",
    "source_log",
    "source_archive",
    "log_entry_id",
    "entry_type",
    "hostname_length",
    "digit_count",
    "hyphen_count",
    "character_entropy",
    "subdomain_depth",
    "metadata_schema_version",
    "certificate_extension_count",
    "issuer_attribute_count",
    "public_key_size",
    "san_wildcard_count",
    "san_idna_count",
    "san_distinct_final_label_count",
    "san_max_length",
    "san_mean_length",
    "san_max_subdomain_depth",
    "san_mean_subdomain_depth",
    "san_max_entropy",
    "san_mean_entropy",
    "has_basic_constraints",
    "basic_constraints_ca",
    "has_key_usage",
    "key_usage_digital_signature",
    "key_usage_key_encipherment",
    "key_usage_key_agreement",
    "has_extended_key_usage",
    "extended_key_usage_count",
    "eku_server_auth",
    "eku_client_auth",
    "eku_code_signing",
    "has_authority_key_identifier",
    "has_subject_key_identifier",
    "has_certificate_policies",
    "certificate_policy_count",
    "has_crl_distribution_points",
    "crl_distribution_point_count",
    "has_authority_information_access",
    "aia_ocsp_count",
    "aia_ca_issuers_count",
    "has_tls_feature",
    "tls_feature_count",
    "has_name_constraints",
    "certificate_version",
    "public_key_algorithm",
    "signature_hash_algorithm",
    "signature_algorithm_family",
    "issuer_organization",
    "issuer_country",
)
RELEASE_COLUMNS = ("record_id", "dataset_split", "cohort_version", *BASE_COLUMNS)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Post-purge split-safe cohort Parquet")
    parser.add_argument("--split-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--cohort-version", required=True)
    parser.add_argument("--pyarrow-path", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_date(value: str, name: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"invalid {name} boundary in split manifest: {value!r}") from exc


def split_for(day: dt.date, boundaries: dict[str, tuple[dt.date, dt.date]]) -> str:
    for split in ("train", "validation", "test"):
        start, end = boundaries[split]
        if start <= day <= end:
            return split
    raise SystemExit(f"collection date {day} is outside the split-manifest calendar range")


def csv_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (dt.date, dt.datetime)):
        text = value.isoformat()
        return text.replace("+00:00", "Z")
    if isinstance(value, bool):
        return int(value)
    return value


def record_id(row: dict[str, Any]) -> str:
    identity = "\x1f".join(
        str(row[column])
        for column in ("hostname", "label", "collection_date", "ct_timestamp", "certificate_fingerprint")
    )
    return "ctph_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def main() -> int:
    args = parse_args()
    if args.pyarrow_path:
        sys.path.insert(0, str(args.pyarrow_path))
    try:
        import pyarrow.parquet as pq
    except ModuleNotFoundError as exc:
        raise SystemExit("PyArrow is required; pass --pyarrow-path /isolated/dependency/path") from exc
    if not args.input.is_file() or not args.split_manifest.is_file():
        raise SystemExit("--input and --split-manifest must be existing files")
    if args.output.exists() or args.manifest_output.exists():
        raise SystemExit("refusing to overwrite an existing release output or manifest")

    manifest = json.loads(args.split_manifest.read_text())
    try:
        split_rule = manifest["fixed_calendar_split_rule"]
        boundaries = {
            split: (parse_date(split_rule[split]["start"], f"{split}.start"), parse_date(split_rule[split]["end"], f"{split}.end"))
            for split in ("train", "validation", "test")
        }
        expected_rows = int(manifest["post_purge"]["rows"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit("split manifest does not have the expected leakage-audit structure") from exc

    parquet = pq.ParquetFile(args.input)
    observed_columns = tuple(parquet.schema_arrow.names)
    if set(observed_columns) != set(BASE_COLUMNS):
        missing = sorted(set(BASE_COLUMNS).difference(observed_columns))
        unexpected = sorted(set(observed_columns).difference(BASE_COLUMNS))
        raise SystemExit(f"input schema differs from release contract; missing={missing}, unexpected={unexpected}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    records: set[str] = set()
    counts: dict[str, Counter[str]] = {split: Counter() for split in ("train", "validation", "test")}
    with args.output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RELEASE_COLUMNS, extrasaction="raise")
        writer.writeheader()
        for batch in parquet.iter_batches(columns=list(BASE_COLUMNS), batch_size=10_000):
            for row in batch.to_pylist():
                day = row["collection_date"]
                if not isinstance(day, dt.date):
                    raise SystemExit("collection_date must be a non-null date")
                if row["label"] not in {"benign", "phish"}:
                    raise SystemExit(f"unexpected supervised label: {row['label']!r}")
                split = split_for(day, boundaries)
                identifier = record_id(row)
                if identifier in records:
                    raise SystemExit("duplicate release record identity; input was not one-row-per-host/certificate observation")
                records.add(identifier)
                release_row = {
                    "record_id": identifier,
                    "dataset_split": split,
                    "cohort_version": args.cohort_version,
                    **{column: csv_value(row[column]) for column in BASE_COLUMNS},
                }
                writer.writerow(release_row)
                rows += 1
                counts[split][str(row["label"])] += 1
    if rows != expected_rows:
        raise SystemExit(f"row count differs from split manifest: CSV={rows}, manifest={expected_rows}")
    if not all(counts[split][label] > 0 for split in counts for label in ("benign", "phish")):
        raise SystemExit("release gate failed: a chronological split lacks a supervised class")

    release_manifest = {
        "release_schema_version": "ct_phishing_standard_csv_v1",
        "cohort_version": args.cohort_version,
        "safety_note": "Complete post-deduplication, post-leakage-purge rows only. No raw URLs, HTML, targets, raw DNS-SAN lists, certificate bytes, serial numbers, public keys, or extension values are included.",
        "input": {"path": str(args.input), "sha256": sha256_file(args.input), "rows": rows},
        "split_manifest": {"path": str(args.split_manifest), "sha256": sha256_file(args.split_manifest)},
        "columns": list(RELEASE_COLUMNS),
        "rows_by_split_and_label": {split: dict(sorted(counts[split].items())) for split in counts},
        "output": {"path": str(args.output), "sha256": sha256_file(args.output), "bytes": args.output.stat().st_size, "rows": rows},
    }
    args.manifest_output.write_text(json.dumps(release_manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(release_manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
