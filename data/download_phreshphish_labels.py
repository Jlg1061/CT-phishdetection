#!/usr/bin/env python3
"""Download a pinned PhreshPhish release and derive the minimal CT label table.

The raw release includes phishing URLs.  This script writes it only to the
explicit restricted --raw-directory, then emits a separate Parquet file with
only normalized hostname, class label, and UTC collection date for CT joins.
It never copies URLs, HTML, targets, or source-row identifiers into that
derivative.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


# PROJECT CONFIGURATION USED: this exact public PhreshPhish snapshot was used
# for the prior experiment.  Changing it means making a new data release.
DEFAULT_REPOSITORY = "phreshphish/phreshphish"
DEFAULT_REVISION = "eca603e0ecd4f698f8d4d226c088659e72681239"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-directory", required=True, type=Path)
    parser.add_argument("--labels-output", required=True, type=Path)
    parser.add_argument("--stats", required=True, type=Path)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--revision", default=DEFAULT_REVISION)
    parser.add_argument("--batch-size", type=int, default=25_000)
    parser.add_argument(
        "--start-date",
        type=dt.date.fromisoformat,
        help="Optional inclusive UTC collection-date lower bound for the restricted label table.",
    )
    parser.add_argument(
        "--end-date",
        type=dt.date.fromisoformat,
        help="Optional inclusive UTC collection-date upper bound for the restricted label table.",
    )
    parser.add_argument("--download-only", action="store_true")
    return parser.parse_args()


def normalise_hostname(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        hostname = urlsplit(value).hostname
    except ValueError:
        return None
    if not hostname:
        return None
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_release(repository: str, revision: str, raw_directory: Path) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ModuleNotFoundError as exc:
        raise SystemExit("huggingface_hub is required; install requirements.txt") from exc
    raw_directory.mkdir(parents=True, exist_ok=True)
    return Path(
        snapshot_download(
            repo_id=repository,
            repo_type="dataset",
            revision=revision,
            allow_patterns=["data/*.parquet"],
            local_dir=str(raw_directory),
        )
    )


def main() -> int:
    args = parse_args()
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be positive")
    if (args.start_date is None) != (args.end_date is None):
        raise SystemExit("--start-date and --end-date must be supplied together")
    if args.start_date and args.end_date and args.end_date < args.start_date:
        raise SystemExit("--end-date precedes --start-date")
    snapshot_root = download_release(args.repository, args.revision, args.raw_directory)
    shards = sorted(snapshot_root.glob("data/*.parquet"))
    if not shards:
        raise SystemExit("the downloaded release contains no data/*.parquet files")
    if args.download_only:
        print(json.dumps({"downloaded_shards": len(shards), "raw_directory": str(snapshot_root)}))
        return 0

    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ModuleNotFoundError as exc:
        raise SystemExit("pyarrow is required; install requirements.txt") from exc

    schema = pa.schema(
        [
            pa.field("hostname", pa.string()),
            pa.field("label", pa.string()),
            pa.field("collection_date", pa.date32()),
        ]
    )
    args.labels_output.parent.mkdir(parents=True, exist_ok=True)
    total_rows = emitted_rows = invalid_hostname_rows = 0
    labels: Counter[str] = Counter()
    dates: list[dt.date] = []
    source_shards: list[dict[str, object]] = []
    with pq.ParquetWriter(args.labels_output, schema=schema, compression="zstd") as writer:
        for shard in shards:
            parquet_file = pq.ParquetFile(shard)
            required = {"url", "label", "date"}
            missing = required.difference(parquet_file.schema_arrow.names)
            if missing:
                raise SystemExit(f"{shard} is missing required columns {sorted(missing)}")
            source_shards.append(
                {
                    "name": shard.name,
                    "rows": parquet_file.metadata.num_rows,
                    "bytes": shard.stat().st_size,
                    "sha256": sha256_file(shard),
                }
            )
            for batch in parquet_file.iter_batches(
                batch_size=args.batch_size, columns=["url", "label", "date"]
            ):
                total_rows += batch.num_rows
                output_rows: list[dict[str, object]] = []
                for row in batch.to_pylist():
                    hostname = normalise_hostname(row["url"])
                    collection_date = row["date"]
                    if hostname is None or not isinstance(collection_date, dt.date):
                        invalid_hostname_rows += 1
                        continue
                    if args.start_date and args.end_date and not (
                        args.start_date <= collection_date <= args.end_date
                    ):
                        continue
                    label = str(row["label"]) if row["label"] is not None else "<null>"
                    output_rows.append(
                        {
                            "hostname": hostname,
                            "label": label,
                            "collection_date": collection_date,
                        }
                    )
                    labels[label] += 1
                    dates.append(collection_date)
                if output_rows:
                    writer.write_table(pa.Table.from_pylist(output_rows, schema=schema))
                    emitted_rows += len(output_rows)

    summary = {
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "source": {
            "repository": args.repository,
            "revision": args.revision,
            "raw_directory": str(snapshot_root),
            "source_shards": source_shards,
        },
        "input_rows": total_rows,
        "emitted_rows": emitted_rows,
        "invalid_or_missing_hostname_or_date_rows": invalid_hostname_rows,
        "rows_by_label": dict(sorted(labels.items())),
        "collection_day_range": {
            "start": str(min(dates)) if dates else None,
            "end": str(max(dates)) if dates else None,
        },
        "requested_collection_day_interval": (
            {"start": str(args.start_date), "end": str(args.end_date)}
            if args.start_date and args.end_date
            else None
        ),
        "output": {
            "path": str(args.labels_output),
            "sha256": sha256_file(args.labels_output),
            "columns": ["hostname", "label", "collection_date"],
        },
        "safety_note": "The derivative contains only normalized hostname, class label, and collection date. It excludes original URLs, HTML, target annotations, and source-row identifiers. The raw download remains restricted because it contains URLs.",
    }
    args.stats.parent.mkdir(parents=True, exist_ok=True)
    args.stats.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
