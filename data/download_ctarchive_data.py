#!/usr/bin/env python3
"""Download and SHA-1-verify selected public CTArchive Static-CT ZIP blocks.

The default configuration is deliberately pinned to the blocks used in this
project's expanded development work.  It is not a generic claim about all CT
logs or a source of benign labels.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote


# PROJECT CONFIGURATION USED: the initial pilot used CTArchive's Internet
# Archive mirror of TrustAsia Log2025A (archive id ct_trustasia_log2025a;
# https://ct2025-a.trustasia.com/log2025a/) and shards 017.zip–024.zip.
# Expansion drivers also pass explicit options for TrustAsia Log2025B and
# Sectigo Elephant 2025H2. Defaults remain the reproducible initial pilot;
# invoke an expansion driver to reproduce an enlarged cohort.
DEFAULT_ARCHIVE_ID = "ct_trustasia_log2025a"
DEFAULT_LOG_URL = "https://ct2025-a.trustasia.com/log2025a/"
DEFAULT_SHARDS = tuple(f"{number:03d}.zip" for number in range(17, 25))
METADATA_URL = "https://archive.org/metadata/{archive_id}"
DOWNLOAD_URL = "https://archive.org/download/{archive_id}/{filename}"
CHUNK_SIZE = 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--archive-id", default=DEFAULT_ARCHIVE_ID)
    parser.add_argument("--log-url", default=DEFAULT_LOG_URL)
    parser.add_argument(
        "--shard",
        action="append",
        dest="shards",
        metavar="NNN.zip",
        help="Archive member to acquire; repeat to override the default 017–024 set.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_shard_names(values: list[str] | None) -> tuple[str, ...]:
    names = tuple(values) if values else DEFAULT_SHARDS
    if not names:
        raise SystemExit("at least one --shard is required")
    for name in names:
        if len(name) != 7 or not name[:3].isdigit() or name[3:] != ".zip":
            raise SystemExit(f"invalid shard name {name!r}; expected NNN.zip")
    return names


def fetch_metadata(archive_id: str, timeout: int) -> dict[str, object]:
    request = urllib.request.Request(
        METADATA_URL.format(archive_id=quote(archive_id, safe="")),
        headers={"User-Agent": "ct-phish-research/1.0 (provenance-first acquisition)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.load(response)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not retrieve Internet Archive metadata: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        raise SystemExit("Internet Archive metadata does not contain a files list")
    return value


def select_members(metadata: dict[str, object], names: tuple[str, ...]) -> list[dict[str, object]]:
    files = metadata["files"]
    by_name = {
        item.get("name"): item
        for item in files
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    selected: list[dict[str, object]] = []
    for name in names:
        item = by_name.get(name)
        if not isinstance(item, dict):
            raise SystemExit(f"{name} is not listed in this Internet Archive item")
        size, sha1 = item.get("size"), item.get("sha1")
        if not isinstance(size, str) or not size.isdecimal() or not isinstance(sha1, str):
            raise SystemExit(f"{name} has no usable publisher size/SHA-1 metadata")
        selected.append({"filename": name, "bytes": int(size), "sha1": sha1.lower()})
    return selected


def download_one(
    *, archive_id: str, member: dict[str, object], destination: Path, timeout: int
) -> str:
    filename = str(member["filename"])
    expected_bytes = int(member["bytes"])
    expected_sha1 = str(member["sha1"])
    target = destination / filename
    destination.mkdir(parents=True, exist_ok=True)

    if target.exists() and target.stat().st_size == expected_bytes:
        if sha1_file(target) == expected_sha1:
            return "verified-existing"
        target.rename(target.with_suffix(target.suffix + ".corrupt"))

    part = target.with_suffix(target.suffix + ".part")
    resume_at = part.stat().st_size if part.exists() else 0
    if resume_at >= expected_bytes:
        part.unlink()
        resume_at = 0
    headers = {"User-Agent": "ct-phish-research/1.0 (CTArchive acquisition)"}
    if resume_at:
        headers["Range"] = f"bytes={resume_at}-"
    url = DOWNLOAD_URL.format(
        archive_id=quote(archive_id, safe=""), filename=quote(filename, safe="")
    )
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_range = response.headers.get("Content-Range", "")
            append = response.status == 206 and content_range.startswith(f"bytes {resume_at}-")
            if resume_at and not append:
                part.unlink()
                resume_at = 0
            progress_at = ((resume_at // (256 * 1024 * 1024)) + 1) * 256 * 1024 * 1024
            with part.open("ab" if append else "wb") as output:
                transferred = resume_at
                for chunk in iter(lambda: response.read(CHUNK_SIZE), b""):
                    output.write(chunk)
                    transferred += len(chunk)
                    if transferred >= progress_at:
                        print(
                            f"progress {filename}: {transferred / 1024**3:.2f} GiB",
                            file=sys.stderr,
                            flush=True,
                        )
                        progress_at += 256 * 1024 * 1024
    except urllib.error.URLError as exc:
        raise SystemExit(f"download failed for {filename}: {exc}") from exc

    if not part.exists() or part.stat().st_size != expected_bytes:
        actual = part.stat().st_size if part.exists() else 0
        raise SystemExit(f"size mismatch for {filename}: expected {expected_bytes}, got {actual}")
    actual_sha1 = sha1_file(part)
    if actual_sha1 != expected_sha1:
        raise SystemExit(f"SHA-1 mismatch for {filename}; leaving the .part file for inspection")
    part.replace(target)
    return "downloaded-and-verified"


def main() -> int:
    args = parse_args()
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    shards = safe_shard_names(args.shards)
    metadata = fetch_metadata(args.archive_id, args.timeout_seconds)
    members = select_members(metadata, shards)
    manifest = {
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "source": "CTArchive Internet Archive mirror",
        "archive_id": args.archive_id,
        "log_url": args.log_url,
        "selected_shards": members,
        "safety_note": "Provenance only; the manifest contains no certificate or hostname data.",
    }
    print(json.dumps({"shards": members, "expected_gib": round(sum(int(m["bytes"]) for m in members) / 1024**3, 2)}))
    if args.dry_run:
        return 0
    args.destination.mkdir(parents=True, exist_ok=True)
    (args.destination / "ctarchive_download_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    results: dict[str, str] = {}
    for member in members:
        results[str(member["filename"])] = download_one(
            archive_id=args.archive_id,
            member=member,
            destination=args.destination,
            timeout=args.timeout_seconds,
        )
        print(json.dumps({"file": member["filename"], "status": results[str(member["filename"])]}), flush=True)
    print(json.dumps({"complete": True, "results": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
