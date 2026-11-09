#!/usr/bin/env python3
"""Sequentially collect a profiled CTArchive range into restricted match tables.

Use only after `probe_ctarchive_static_zip.py` verifies that the requested
shards intersect a specified label interval's pre-collection SCT window. The
script resumes verified downloads, writes one restricted match table per shard,
and removes a raw ZIP only after its Parquet output and summary exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-id", required=True)
    parser.add_argument("--log-url", required=True)
    parser.add_argument("--source-tag", required=True, help="Stable snake_case source identifier")
    parser.add_argument("--first-shard", required=True, type=int)
    parser.add_argument("--last-shard", required=True, type=int)
    parser.add_argument("--labels", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path, help="Per-source working directory")
    parser.add_argument("--window-days", type=int, default=30)
    parser.add_argument("--python-path", type=Path, action="append", default=[])
    parser.add_argument("--keep-raw", action="store_true")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], environment: dict[str, str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, env=environment)


def main() -> int:
    args = parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_]*", args.source_tag):
        raise SystemExit("--source-tag must be lowercase snake_case")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", args.archive_id):
        raise SystemExit("--archive-id has unsupported characters")
    if not 0 <= args.first_shard <= args.last_shard <= 999:
        raise SystemExit("shard range must be within 000–999 and ascending")
    if args.window_days < 1:
        raise SystemExit("--window-days must be positive")
    if not args.labels.is_file():
        raise SystemExit(f"label input does not exist: {args.labels}")

    raw = args.root / "raw"
    derived = args.root / "derived"
    raw.mkdir(parents=True, exist_ok=True)
    derived.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    if args.python_path:
        environment["PYTHONPATH"] = os.pathsep.join(
            [*(str(path) for path in args.python_path), environment.get("PYTHONPATH", "")]
        )
    downloader = PROJECT_ROOT / "download_ctarchive_data.py"
    extractor = PROJECT_ROOT / "process_ctarchive_matches.py"
    completed: list[dict[str, object]] = []
    for number in range(args.first_shard, args.last_shard + 1):
        shard = f"{number:03d}"
        archive = raw / f"{shard}.zip"
        matches = derived / f"{args.source_tag}_{args.window_days}d_{shard}_matches.parquet"
        summary = derived / f"{args.source_tag}_{shard}_match_summary.json"
        if not matches.is_file() or not summary.is_file():
            run(
                [
                    sys.executable,
                    str(downloader),
                    "--archive-id",
                    args.archive_id,
                    "--log-url",
                    args.log_url,
                    "--shard",
                    archive.name,
                    "--destination",
                    str(raw),
                ],
                environment,
            )
            run(
                [
                    sys.executable,
                    str(extractor),
                    "--archive",
                    str(archive),
                    "--labels",
                    str(args.labels),
                    "--output",
                    str(matches),
                    "--stats",
                    str(summary),
                    "--window-days",
                    str(args.window_days),
                ],
                environment,
            )
            if not args.keep_raw:
                archive.unlink()
                print(f"removed verified, processed raw archive {archive}", flush=True)
        details = json.loads(summary.read_text())
        completed.append(
            {
                "shard": archive.name,
                "matches": {"path": str(matches), "sha256": sha256_file(matches), "bytes": matches.stat().st_size},
                "temporally_eligible_exact_matches": details["scan_counts"]["temporally_eligible_exact_matches"],
                "sct_min_utc": details["ct_sct_timestamp_min_utc"],
                "sct_max_utc": details["ct_sct_timestamp_max_utc"],
            }
        )
    source_manifest = {
        "source_tag": args.source_tag,
        "archive_id": args.archive_id,
        "log_url": args.log_url,
        "labels": {"path": str(args.labels), "sha256": sha256_file(args.labels)},
        "window_days": args.window_days,
        "completed_shards": completed,
        "safety_note": "Restricted exact CT/label matches only. Raw CT ZIPs are removed after successful processing unless --keep-raw is specified.",
    }
    manifest_path = derived / f"{args.source_tag}_source_manifest.json"
    manifest_path.write_text(json.dumps(source_manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(source_manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
