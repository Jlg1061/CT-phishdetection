#!/usr/bin/env python3
"""Recreate the checkpoint CT/PhreshPhish cohort and its clean CSV release.

One command downloads the pinned PhreshPhish label release, acquires the
configured CTArchive shards with publisher SHA-1 verification, retains only
temporally eligible exact DNS-SAN matches, deduplicates the restricted match
tables, removes cross-split certificate/domain overlap, and writes the fixed
64-column CSV.  It never labels unmatched CT names as benign.

The default profile is the current checkpoint experiment:

* PhreshPhish ``eca603e0ecd4f698f8d4d226c088659e72681239``;
* label collection days 2025-09-05 through 2025-11-05 (UTC, inclusive);
* a 30-day SCT window immediately preceding each collection day;
* TrustAsia Log2025A and Log2025B shards 017--024, plus Sectigo Elephant
  2025H2 shards 039--072.

Changing the label dates, SCT window, or CT source specifications produces a
new cohort.  Treat it as a new experimental release rather than a replacement
for the checkpoint profile.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
PHRESHPHISH_REPOSITORY = "phreshphish/phreshphish"
PHRESHPHISH_REVISION = "eca603e0ecd4f698f8d4d226c088659e72681239"

# This is the immutable publicsuffix/list commit whose file was used for the
# current leakage audit.  The SHA-256 is verified after download.
PINNED_PSL_URL = (
    "https://raw.githubusercontent.com/publicsuffix/list/"
    "9e8325c62adb9f7c6211cb7c4f6970a27fcb67f1/public_suffix_list.dat"
)
PINNED_PSL_SHA256 = "87d2e11f3602b504fc5dbea9218429a4ce3c0f62aa6ce7a1371024add024baed"
PINNED_PSL_FILENAME = "public_suffix_list_2026-10-26.dat"


@dataclass(frozen=True)
class SourceSpec:
    """One range-profiled CTArchive Static-CT source."""

    tag: str
    archive_id: str
    log_url: str
    first_shard: int
    last_shard: int

    def shard_numbers(self) -> range:
        return range(self.first_shard, self.last_shard + 1)


DEFAULT_SOURCES = (
    SourceSpec(
        "trustasia_log2025a",
        "ct_trustasia_log2025a",
        "https://ct2025-a.trustasia.com/log2025a/",
        17,
        24,
    ),
    SourceSpec(
        "trustasia_log2025b",
        "ct_trustasia_log2025b",
        "https://ct2025-b.trustasia.com/log2025b/",
        17,
        24,
    ),
    SourceSpec(
        "sectigo_elephant2025h2",
        "ct_sectigo_elephant2025h2",
        "https://elephant2025h2.ct.sectigo.com/",
        39,
        72,
    ),
)
SPLITS = ("train", "validation", "test")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-directory",
        type=Path,
        default=Path("/mnt/ml-data/ct_phishing_reproduction"),
        help="Restricted working directory for raw inputs, derivatives, and the release.",
    )
    parser.add_argument("--label-start-date", type=dt.date.fromisoformat, default=dt.date(2025, 9, 5))
    parser.add_argument("--label-end-date", type=dt.date.fromisoformat, default=dt.date(2025, 11, 5))
    parser.add_argument("--window-days", type=int, default=30)
    parser.add_argument(
        "--ct-source",
        action="append",
        metavar="TAG|ARCHIVE_ID|LOG_URL|FIRST_SHARD|LAST_SHARD",
        help=(
            "Replace the default source list with this range-profiled source. "
            "Repeat for multiple sources; shard bounds are inclusive."
        ),
    )
    parser.add_argument(
        "--public-suffix-list",
        type=Path,
        help="Optional already-downloaded PSL snapshot. The default downloads the pinned checkpoint snapshot.",
    )
    parser.add_argument("--python-path", type=Path, action="append", default=[])
    parser.add_argument("--keep-raw", action="store_true", help="Retain verified CT ZIPs after processing.")
    parser.add_argument(
        "--cohort-version",
        help="Release identifier. The default is derived from the selected labels and SCT window.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the resolved profile without downloading or writing.")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], environment: dict[str, str], dry_run: bool) -> None:
    print("+", " ".join(command), flush=True)
    if not dry_run:
        subprocess.run(command, check=True, env=environment)


def parse_source(value: str) -> SourceSpec:
    parts = value.split("|")
    if len(parts) != 5:
        raise SystemExit(
            "--ct-source must be TAG|ARCHIVE_ID|LOG_URL|FIRST_SHARD|LAST_SHARD"
        )
    tag, archive_id, log_url, first, last = parts
    if not re.fullmatch(r"[a-z0-9][a-z0-9_]*", tag):
        raise SystemExit(f"invalid CT source tag: {tag!r}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", archive_id):
        raise SystemExit(f"invalid CTArchive id: {archive_id!r}")
    if not log_url.startswith("https://"):
        raise SystemExit("CT log URLs must use https://")
    try:
        first_shard, last_shard = int(first), int(last)
    except ValueError as exc:
        raise SystemExit("CT shard bounds must be integers") from exc
    if not 0 <= first_shard <= last_shard <= 999:
        raise SystemExit("CT shard bounds must be ascending numbers in 000--999")
    return SourceSpec(tag, archive_id, log_url, first_shard, last_shard)


def resolved_sources(values: list[str] | None) -> tuple[SourceSpec, ...]:
    sources = tuple(parse_source(value) for value in values) if values else DEFAULT_SOURCES
    tags = [source.tag for source in sources]
    if len(set(tags)) != len(tags):
        raise SystemExit("each --ct-source needs a unique tag")
    return sources


def configured_environment(python_paths: list[Path]) -> dict[str, str]:
    environment = os.environ.copy()
    if python_paths:
        environment["PYTHONPATH"] = os.pathsep.join(
            [*(str(path) for path in python_paths), environment.get("PYTHONPATH", "")]
        )
    return environment


def import_arrow(python_paths: list[Path]) -> tuple[Any, Any]:
    for path in reversed(python_paths):
        sys.path.insert(0, str(path))
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ModuleNotFoundError as exc:
        raise SystemExit("PyArrow is required; install requirements.txt or provide --python-path") from exc
    return pa, pq


def ensure_pinned_psl(path: Path, dry_run: bool) -> Path:
    if path.is_file():
        actual = sha256_file(path)
        if actual != PINNED_PSL_SHA256:
            raise SystemExit(
                f"pinned public suffix list checksum differs: expected {PINNED_PSL_SHA256}, got {actual}"
            )
        return path
    if dry_run:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".part")
    request = urllib.request.Request(PINNED_PSL_URL, headers={"User-Agent": "ct-phish-research/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as handle:
            while chunk := response.read(1024 * 1024):
                handle.write(chunk)
    except urllib.error.URLError as exc:
        raise SystemExit(f"could not download the pinned public suffix list: {exc}") from exc
    actual = sha256_file(temporary)
    if actual != PINNED_PSL_SHA256:
        temporary.unlink(missing_ok=True)
        raise SystemExit(
            f"downloaded public suffix list checksum differs: expected {PINNED_PSL_SHA256}, got {actual}"
        )
    temporary.replace(path)
    return path


def read_psl(path: Path) -> tuple[set[str], set[str], set[str]]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exceptions: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:].encode("idna").decode("ascii").lower())
        elif line.startswith("*."):
            wildcard.add(line[2:].encode("idna").decode("ascii").lower())
        else:
            exact.add(line.encode("idna").decode("ascii").lower())
    if not exact:
        raise SystemExit(f"no rules found in public suffix list {path}")
    return exact, wildcard, exceptions


def registrable_domain(
    hostname: str, exact: set[str], wildcard: set[str], exceptions: set[str]
) -> str:
    labels = hostname.rstrip(".").lower().split(".")
    if not labels or any(not label for label in labels):
        raise SystemExit("invalid hostname encountered while auditing splits")
    suffix_labels = 1
    for start in range(len(labels)):
        candidate = ".".join(labels[start:])
        candidate_length = len(labels) - start
        if candidate in exceptions:
            suffix_labels = candidate_length - 1
            break
        if candidate in exact:
            suffix_labels = max(suffix_labels, candidate_length)
        if start + 1 < len(labels) and ".".join(labels[start + 1 :]) in wildcard:
            suffix_labels = max(suffix_labels, candidate_length)
    return hostname.lower() if len(labels) <= suffix_labels else ".".join(labels[-(suffix_labels + 1) :])


def matching_label_table(
    *,
    work: Path,
    start: dt.date,
    end: dt.date,
    environment: dict[str, str],
    dry_run: bool,
) -> Path:
    labels = work / "labels" / f"phreshphish_labels_{start}_to_{end}.parquet"
    stats = labels.with_name(labels.stem + "_summary.json")
    expected_interval = {"start": str(start), "end": str(end)}
    if labels.is_file() and stats.is_file():
        details = json.loads(stats.read_text())
        source = details.get("source", {})
        if (
            source.get("repository") == PHRESHPHISH_REPOSITORY
            and source.get("revision") == PHRESHPHISH_REVISION
            and details.get("requested_collection_day_interval") == expected_interval
        ):
            return labels
        raise SystemExit(
            f"existing label derivative does not match this configuration: {labels}; use another --work-directory"
        )
    raw = work / "raw_phreshphish"
    script = PROJECT_ROOT / "download_phreshphish_labels.py"
    run(
        [
            sys.executable,
            str(script),
            "--raw-directory",
            str(raw),
            "--labels-output",
            str(labels),
            "--stats",
            str(stats),
            "--repository",
            PHRESHPHISH_REPOSITORY,
            "--revision",
            PHRESHPHISH_REVISION,
            "--start-date",
            str(start),
            "--end-date",
            str(end),
        ],
        environment,
        dry_run,
    )
    return labels


def collect_source(
    *,
    source: SourceSpec,
    labels: Path,
    work: Path,
    window_days: int,
    python_paths: list[Path],
    keep_raw: bool,
    environment: dict[str, str],
    dry_run: bool,
) -> list[Path]:
    root = work / "ctarchive" / source.tag
    command = [
        sys.executable,
        str(PROJECT_ROOT / "collect_ctarchive_range.py"),
        "--archive-id",
        source.archive_id,
        "--log-url",
        source.log_url,
        "--source-tag",
        source.tag,
        "--first-shard",
        str(source.first_shard),
        "--last-shard",
        str(source.last_shard),
        "--labels",
        str(labels),
        "--root",
        str(root),
        "--window-days",
        str(window_days),
    ]
    for path in python_paths:
        command.extend(["--python-path", str(path)])
    if keep_raw:
        command.append("--keep-raw")
    run(command, environment, dry_run)
    return [
        root / "derived" / f"{source.tag}_{window_days}d_{number:03d}_matches.parquet"
        for number in source.shard_numbers()
    ]


def assemble_candidates(inputs: list[Path], output: Path, stats: Path, pa: Any, pq: Any) -> None:
    schema = None
    rows: list[dict[str, object]] = []
    input_manifest: list[dict[str, object]] = []
    for path in inputs:
        if not path.is_file():
            raise SystemExit(f"expected processed match table is missing: {path}")
        table = pq.read_table(path)
        if schema is None:
            schema = table.schema
        elif table.schema != schema:
            raise SystemExit(f"processed metadata schema differs for {path}")
        rows.extend(table.to_pylist())
        input_manifest.append(
            {"path": str(path), "rows": table.num_rows, "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    if schema is None:
        raise SystemExit("no CT match inputs were supplied")

    labels_per_host: dict[str, set[str]] = defaultdict(set)
    earliest_day: dict[tuple[str, str], dt.date] = {}
    for row in rows:
        hostname, label, day = row.get("hostname"), row.get("label"), row.get("collection_date")
        if not isinstance(hostname, str) or label not in {"benign", "phish"} or not isinstance(day, dt.date):
            raise SystemExit("processed match table contains an invalid supervised record")
        labels_per_host[hostname].add(label)
        key = (hostname, label)
        if key not in earliest_day or day < earliest_day[key]:
            earliest_day[key] = day
    conflicts = {hostname for hostname, values in labels_per_host.items() if len(values) > 1}

    primary: dict[tuple[str, str], dict[str, object]] = {}
    dropped_conflicts = dropped_later_days = 0
    for row in rows:
        hostname, label, day = str(row["hostname"]), str(row["label"]), row["collection_date"]
        if hostname in conflicts:
            dropped_conflicts += 1
            continue
        if day != earliest_day[(hostname, label)]:
            dropped_later_days += 1
            continue
        key = (hostname, label)
        existing = primary.get(key)
        if existing is None or str(row["ct_timestamp"]) > str(existing["ct_timestamp"]):
            primary[key] = row

    output_rows = sorted(primary.values(), key=lambda row: (row["collection_date"], row["hostname"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(output_rows, schema=schema), output, compression="zstd")
    counts = Counter(str(row["label"]) for row in output_rows)
    stats.write_text(
        json.dumps(
            {
                "generated_at_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
                "deduplication_rule": "For each non-conflicted exact hostname and label, retain the earliest collection day and most recent eligible SCT.",
                "safety_note": "Restricted CT/Phresh metadata only; no raw URLs, HTML, target annotations, or unmatched CT hostnames.",
                "inputs": input_manifest,
                "input_rows": len(rows),
                "conflicting_label_hostnames_excluded": len(conflicts),
                "rows_dropped_for_conflicting_label_hostnames": dropped_conflicts,
                "rows_dropped_for_later_collection_dates": dropped_later_days,
                "output_rows_by_label": dict(sorted(counts.items())),
                "output": {"path": str(output), "rows": len(output_rows), "sha256": sha256_file(output)},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def date_to_split(day: dt.date, start: dt.date, train_days: int, validation_days: int) -> str:
    offset = (day - start).days
    return "train" if offset < train_days else "validation" if offset < train_days + validation_days else "test"


def identity_audit(identities: list[str], assignments: list[str], identity_name: str) -> tuple[set[str], dict[str, int | str]]:
    split_sets: dict[str, set[str]] = defaultdict(set)
    counts: Counter[str] = Counter()
    for identity, split in zip(identities, assignments, strict=True):
        split_sets[identity].add(split)
        counts[identity] += 1
    overlaps = {identity for identity, splits in split_sets.items() if len(splits) > 1}
    return overlaps, {
        "identity": identity_name,
        "groups_total": len(split_sets),
        "cross_split_groups": len(overlaps),
        "rows_in_cross_split_groups": sum(counts[identity] for identity in overlaps),
    }


def split_summary(rows: list[dict[str, object]], assignments: list[str]) -> dict[str, object]:
    counts: dict[str, Counter[str]] = {split: Counter() for split in SPLITS}
    sources: dict[str, Counter[str]] = {split: Counter() for split in SPLITS}
    for row, split in zip(rows, assignments, strict=True):
        counts[split][str(row["label"])] += 1
        sources[split][str(row["source_archive"])] += 1
    return {
        "rows": len(rows),
        "rows_by_split_and_label": {split: dict(sorted(counts[split].items())) for split in SPLITS},
        "rows_by_split_and_source_archive": {split: dict(sorted(sources[split].items())) for split in SPLITS},
    }


def freeze_splits(input_path: Path, psl_path: Path, output: Path, stats: Path, pa: Any, pq: Any) -> None:
    table = pq.read_table(input_path)
    required = {"hostname", "label", "collection_date", "certificate_fingerprint", "source_archive"}
    if missing := required.difference(table.column_names):
        raise SystemExit(f"candidate cohort lacks required fields: {sorted(missing)}")
    rows = table.to_pylist()
    if not rows:
        raise SystemExit("candidate cohort is empty")
    dates = [row["collection_date"] for row in rows]
    if not all(isinstance(day, dt.date) for day in dates):
        raise SystemExit("candidate cohort contains an invalid collection date")
    start, end = min(dates), max(dates)
    calendar_days = (end - start).days + 1
    train_days, validation_days = int(calendar_days * 0.60), int(calendar_days * 0.20)
    if min(train_days, validation_days, calendar_days - train_days - validation_days) < 1:
        raise SystemExit("selected label period is too short for 60/20/20 chronological splits")
    assignments = [date_to_split(day, start, train_days, validation_days) for day in dates]
    exact, wildcard, exceptions = read_psl(psl_path)
    domains = [registrable_domain(str(row["hostname"]), exact, wildcard, exceptions) for row in rows]
    fingerprints = [str(row["certificate_fingerprint"]) for row in rows]
    hostnames = [str(row["hostname"]) for row in rows]
    cert_overlap, cert_audit = identity_audit(fingerprints, assignments, "leaf_certificate_sha256")
    domain_overlap, domain_audit = identity_audit(domains, assignments, "psl_registrable_domain")
    _, host_audit = identity_audit(hostnames, assignments, "exact_hostname")
    purged = {
        index
        for index, (fingerprint, domain) in enumerate(zip(fingerprints, domains, strict=True))
        if fingerprint in cert_overlap or domain in domain_overlap
    }
    retained_rows = [row for index, row in enumerate(rows) if index not in purged]
    retained_assignments = [split for index, split in enumerate(assignments) if index not in purged]
    retained_domains = [domain for index, domain in enumerate(domains) if index not in purged]
    retained_fingerprints = [value for index, value in enumerate(fingerprints) if index not in purged]
    remaining_cert, remaining_cert_audit = identity_audit(retained_fingerprints, retained_assignments, "leaf_certificate_sha256")
    remaining_domain, remaining_domain_audit = identity_audit(retained_domains, retained_assignments, "psl_registrable_domain")
    if remaining_cert or remaining_domain:
        raise SystemExit("cross-split identity purge did not converge")

    output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(retained_rows, schema=table.schema), output, compression="zstd")
    post = split_summary(retained_rows, retained_assignments)
    post_counts = post["rows_by_split_and_label"]
    train_end = start + dt.timedelta(days=train_days - 1)
    validation_end = train_end + dt.timedelta(days=validation_days)
    stats.write_text(
        json.dumps(
            {
                "generated_at_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
                "safety_note": "Aggregate-only split manifest; identities and raw phishing artifacts are not emitted here.",
                "input": {"path": str(input_path), "rows": len(rows), "sha256": sha256_file(input_path)},
                "public_suffix_list": {"path": str(psl_path), "sha256": sha256_file(psl_path)},
                "fixed_calendar_split_rule": {
                    "rule": "floor(0.60*N) earliest calendar days=train; floor(0.20*N) following days=validation; remaining latest days=test",
                    "calendar_day_count": calendar_days,
                    "train": {"start": str(start), "end": str(train_end), "calendar_days": train_days},
                    "validation": {"start": str(train_end + dt.timedelta(days=1)), "end": str(validation_end), "calendar_days": validation_days},
                    "test": {"start": str(validation_end + dt.timedelta(days=1)), "end": str(end), "calendar_days": calendar_days - train_days - validation_days},
                },
                "pre_purge": split_summary(rows, assignments),
                "pre_purge_identity_audit": {"exact_hostname": host_audit, "leaf_certificate_sha256": cert_audit, "psl_registrable_domain": domain_audit},
                "cross_split_purge_policy": "Remove every row whose leaf-certificate SHA-256 or PSL registrable-domain group crosses chronological partitions; do not backdate a later label.",
                "rows_removed_by_cross_split_purge": len(purged),
                "post_purge": post,
                "post_purge_identity_audit": {"leaf_certificate_sha256": remaining_cert_audit, "psl_registrable_domain": remaining_domain_audit},
                "post_purge_gate": {
                    "both_direct_comparison_classes_in_each_split": {split: all(post_counts[split].get(label, 0) > 0 for label in ("benign", "phish")) for split in SPLITS},
                    "at_least_200_phish_rows_total": sum(post_counts[split].get("phish", 0) for split in SPLITS) >= 200,
                },
                "output": {"path": str(output), "rows": len(retained_rows), "sha256": sha256_file(output)},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main() -> int:
    args = parse_args()
    if args.label_end_date < args.label_start_date:
        raise SystemExit("--label-end-date precedes --label-start-date")
    if args.window_days < 1:
        raise SystemExit("--window-days must be positive")
    sources = resolved_sources(args.ct_source)
    version = args.cohort_version or f"ctph_{args.label_start_date}_to_{args.label_end_date}_{args.window_days}d"
    work = args.work_directory.resolve()
    psl = args.public_suffix_list or work / "inputs" / PINNED_PSL_FILENAME
    plan = {
        "profile": "checkpoint_2025_default" if not args.ct_source else "custom",
        "work_directory": str(work),
        "phreshphish": {"repository": PHRESHPHISH_REPOSITORY, "revision": PHRESHPHISH_REVISION},
        "label_interval_utc": {"start": str(args.label_start_date), "end": str(args.label_end_date)},
        "sct_window_days": args.window_days,
        "sources": [source.__dict__ for source in sources],
        "public_suffix_list": {"path": str(psl), "sha256": PINNED_PSL_SHA256 if args.public_suffix_list is None else "caller_supplied"},
        "cohort_version": version,
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    work.mkdir(parents=True, exist_ok=True)
    environment = configured_environment(args.python_path)
    if args.public_suffix_list is not None:
        if not psl.is_file():
            raise SystemExit(f"--public-suffix-list does not exist: {psl}")
        plan["public_suffix_list"]["sha256"] = sha256_file(psl)
    else:
        ensure_pinned_psl(psl, dry_run=False)
    labels = matching_label_table(
        work=work,
        start=args.label_start_date,
        end=args.label_end_date,
        environment=environment,
        dry_run=False,
    )
    tables: list[Path] = []
    for source in sources:
        tables.extend(
            collect_source(
                source=source,
                labels=labels,
                work=work,
                window_days=args.window_days,
                python_paths=args.python_path,
                keep_raw=args.keep_raw,
                environment=environment,
                dry_run=False,
            )
        )

    pa, pq = import_arrow(args.python_path)
    cohort = work / "cohort"
    candidates, candidate_stats = cohort / "candidates.parquet", cohort / "candidates_manifest.json"
    split_safe, split_stats = cohort / "split_safe.parquet", cohort / "split_manifest.json"
    assemble_candidates(tables, candidates, candidate_stats, pa, pq)
    freeze_splits(candidates, psl, split_safe, split_stats, pa, pq)

    release = work / "release"
    csv_path = release / "ct_phishing_records.csv"
    csv_manifest = release / "ct_phishing_records_manifest.json"
    if csv_path.exists() != csv_manifest.exists():
        raise SystemExit("incomplete existing release output; use a new --work-directory")
    if not csv_path.exists():
        run(
            [
                sys.executable,
                str(PROJECT_ROOT / "build_standardized_release_csv.py"),
                "--input",
                str(split_safe),
                "--split-manifest",
                str(split_stats),
                "--output",
                str(csv_path),
                "--manifest-output",
                str(csv_manifest),
                "--cohort-version",
                version,
            ],
            environment,
            dry_run=False,
        )

    release_details = json.loads(csv_manifest.read_text())
    run_manifest = {
        **plan,
        "safety_note": "Unmatched CT names are never treated as benign. The final CSV contains only post-deduplication, post-leakage-purge CT/PhreshPhish matches and no raw URLs, HTML, target annotations, CT certificate bytes, or raw DNS-SAN lists.",
        "release": release_details["output"],
        "release_manifest": {"path": str(csv_manifest), "sha256": sha256_file(csv_manifest)},
        "candidate_manifest": {"path": str(candidate_stats), "sha256": sha256_file(candidate_stats)},
        "split_manifest": {"path": str(split_stats), "sha256": sha256_file(split_stats)},
    }
    manifest_path = work / "reproduction_manifest.json"
    manifest_path.write_text(json.dumps(run_manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"complete": True, "csv": str(csv_path), "rows": release_details["output"]["rows"], "manifest": str(manifest_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
