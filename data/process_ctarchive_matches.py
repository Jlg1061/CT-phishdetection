#!/usr/bin/env python3
"""Create restricted, rich CT/PhreshPhish exact-match data from one CT ZIP.

For each locally parsed certificate, this program considers only an exact,
non-wildcard DNS-SAN hostname that appears in the minimal label table.  It
keeps a row only when the SCT timestamp is in the configured interval before
the label's UTC collection day.  Unmatched CT entries are never written and
are never called benign.

The output contains aggregate certificate properties available at SCT time.
It deliberately excludes raw URLs, HTML, targets, unmatched hostnames, raw
DNS-SAN lists, certificate bytes, serial numbers, public keys, and extension
values.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID


CHUNK_RECORDS = 10_000
FEATURE_SCHEMA_VERSION = "rich_certificate_metadata_v1"

CERTIFICATE_METADATA_NUMERIC_FIELDS = (
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
)

CERTIFICATE_METADATA_CATEGORICAL_FIELDS = (
    "certificate_version",
    "public_key_algorithm",
    "signature_hash_algorithm",
    "signature_algorithm_family",
    "issuer_organization",
    "issuer_country",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="Verified local CTArchive ZIP")
    parser.add_argument("--labels", required=True, type=Path, help="Minimal label Parquet from download_phreshphish_labels.py")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--stats", required=True, type=Path)
    parser.add_argument("--window-days", type=int, default=30)
    parser.add_argument("--max-tiles", type=int, help="Optional bounded parser smoke-test limit")
    return parser.parse_args()


def normalise_hostname(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    wildcard = value.startswith("*.")
    bare = value[2:] if wildcard else value
    bare = bare.encode("idna").decode("ascii")
    return "*." + bare if wildcard else bare


def hostname_features(hostname: str) -> dict[str, Any]:
    labels = [label for label in hostname.split(".") if label]
    counts = Counter(hostname)
    length = len(hostname)
    entropy = (
        -sum((count / length) * math.log2(count / length) for count in counts.values())
        if length
        else 0.0
    )
    return {
        "hostname_length": length,
        "digit_count": sum(char.isdigit() for char in hostname),
        "hyphen_count": hostname.count("-"),
        "character_entropy": round(entropy, 6),
        "subdomain_depth": max(0, len(labels) - 2),
    }


def take_u16(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(blob):
        raise ValueError("truncated uint16 length")
    length = int.from_bytes(blob[offset : offset + 2], "big")
    offset += 2
    end = offset + length
    if end > len(blob):
        raise ValueError("truncated uint16 payload")
    return blob[offset:end], end


def take_u24(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 3 > len(blob):
        raise ValueError("truncated uint24 length")
    length = int.from_bytes(blob[offset : offset + 3], "big")
    offset += 3
    end = offset + length
    if end > len(blob):
        raise ValueError("truncated uint24 payload")
    return blob[offset:end], end


def read_tile_leaf(blob: bytes, offset: int) -> tuple[int, str, bytes, int]:
    """Read Static-CT TileLeaf framing and return timestamp, type, full DER, end."""
    if offset + 10 > len(blob):
        raise ValueError("truncated TileLeaf timestamp or entry type")
    timestamp_ms = int.from_bytes(blob[offset : offset + 8], "big")
    kind = int.from_bytes(blob[offset + 8 : offset + 10], "big")
    offset += 10
    if kind == 0:
        certificate, offset = take_u24(blob, offset)
        entry_type = "x509"
    elif kind == 1:
        if offset + 32 > len(blob):
            raise ValueError("truncated precertificate issuer key hash")
        offset += 32
        _, offset = take_u24(blob, offset)
        certificate = b""
        entry_type = "precert"
    else:
        raise ValueError(f"unsupported RFC 6962 entry type {kind}")
    _, offset = take_u16(blob, offset)
    if kind == 1:
        certificate, offset = take_u24(blob, offset)
    _, offset = take_u16(blob, offset)
    return timestamp_ms, entry_type, certificate, offset


def data_tile_index(name: str) -> int:
    tile_path = name.removeprefix("tile/data/").split(".p/", 1)[0]
    index = 0
    for component in tile_path.split("/"):
        component = component[1:] if component.startswith("x") else component
        if not component.isdecimal():
            raise ValueError(f"unexpected data-tile path: {name}")
        index = index * 1000 + int(component)
    return index


def iso_utc(timestamp_ms: int) -> str:
    return dt.datetime.fromtimestamp(timestamp_ms / 1000, dt.UTC).isoformat().replace("+00:00", "Z")


def certificate_time(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_labels(path: Path) -> dict[str, list[tuple[str, dt.date]]]:
    try:
        import pyarrow.parquet as pq
    except ModuleNotFoundError as exc:
        raise SystemExit("pyarrow is required; install requirements.txt") from exc
    table = pq.read_table(path, columns=["hostname", "label", "collection_date"])
    labels: dict[str, list[tuple[str, dt.date]]] = {}
    for row in table.to_pylist():
        hostname, label, collection_date = row["hostname"], row["label"], row["collection_date"]
        if isinstance(hostname, str) and isinstance(label, str) and isinstance(collection_date, dt.date):
            labels.setdefault(hostname, []).append((label, collection_date))
    if not labels:
        raise SystemExit("label table contained no usable hostname, label, collection_date rows")
    return labels


def extension_value(certificate: x509.Certificate, extension_class: type[Any]) -> Any | None:
    try:
        return certificate.extensions.get_extension_for_class(extension_class).value
    except x509.ExtensionNotFound:
        return None


def name_attribute(certificate_name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    values = [str(attribute.value).strip().lower() for attribute in certificate_name.get_attributes_for_oid(oid)]
    return values[0] if values else "__missing__"


def public_key_metadata(certificate: x509.Certificate) -> tuple[str, int]:
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", int(key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", int(key.key_size)
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa", int(key.key_size)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "ed448", 456
    return "other", 0


def signature_metadata(certificate: x509.Certificate) -> tuple[str, str]:
    try:
        hash_algorithm = certificate.signature_hash_algorithm
        hash_name = hash_algorithm.name.lower() if hash_algorithm is not None else "none"
    except UnsupportedAlgorithm:
        hash_name = "unsupported"
    oid_name = (certificate.signature_algorithm_oid._name or "").lower()
    if "rsa" in oid_name:
        family = "rsa"
    elif "ecdsa" in oid_name:
        family = "ecdsa"
    elif "ed25519" in oid_name:
        family = "ed25519"
    elif "ed448" in oid_name:
        family = "ed448"
    elif "dsa" in oid_name:
        family = "dsa"
    else:
        family = "other"
    return hash_name, family


def key_usage_flags(value: x509.KeyUsage | None) -> dict[str, int]:
    if value is None:
        return {
            "has_key_usage": 0,
            "key_usage_digital_signature": 0,
            "key_usage_key_encipherment": 0,
            "key_usage_key_agreement": 0,
        }
    return {
        "has_key_usage": 1,
        "key_usage_digital_signature": int(value.digital_signature),
        "key_usage_key_encipherment": int(value.key_encipherment),
        "key_usage_key_agreement": int(value.key_agreement),
    }


def extended_key_usage_flags(value: x509.ExtendedKeyUsage | None) -> dict[str, int]:
    if value is None:
        return {
            "has_extended_key_usage": 0,
            "extended_key_usage_count": 0,
            "eku_server_auth": 0,
            "eku_client_auth": 0,
            "eku_code_signing": 0,
        }
    values = set(value)
    return {
        "has_extended_key_usage": 1,
        "extended_key_usage_count": len(values),
        "eku_server_auth": int(ExtendedKeyUsageOID.SERVER_AUTH in values),
        "eku_client_auth": int(ExtendedKeyUsageOID.CLIENT_AUTH in values),
        "eku_code_signing": int(ExtendedKeyUsageOID.CODE_SIGNING in values),
    }


def san_structure_features(normalized_names: list[str]) -> dict[str, float | int]:
    names = [name[2:] if name.startswith("*.") else name for name in normalized_names]
    lexical = [hostname_features(name) for name in names]
    if not lexical:
        return {
            "san_wildcard_count": 0, "san_idna_count": 0, "san_distinct_final_label_count": 0,
            "san_max_length": 0, "san_mean_length": 0.0, "san_max_subdomain_depth": 0,
            "san_mean_subdomain_depth": 0.0, "san_max_entropy": 0.0, "san_mean_entropy": 0.0,
        }
    return {
        "san_wildcard_count": sum(name.startswith("*.") for name in normalized_names),
        "san_idna_count": sum("xn--" in name for name in names),
        "san_distinct_final_label_count": len({name.rsplit(".", 1)[-1] for name in names}),
        "san_max_length": max(int(item["hostname_length"]) for item in lexical),
        "san_mean_length": sum(float(item["hostname_length"]) for item in lexical) / len(lexical),
        "san_max_subdomain_depth": max(int(item["subdomain_depth"]) for item in lexical),
        "san_mean_subdomain_depth": sum(float(item["subdomain_depth"]) for item in lexical) / len(lexical),
        "san_max_entropy": max(float(item["character_entropy"]) for item in lexical),
        "san_mean_entropy": sum(float(item["character_entropy"]) for item in lexical) / len(lexical),
    }


def certificate_metadata_features(certificate: x509.Certificate, normalized_names: list[str]) -> dict[str, Any]:
    public_key_algorithm, public_key_size = public_key_metadata(certificate)
    signature_hash_algorithm, signature_algorithm_family = signature_metadata(certificate)
    basic_constraints = extension_value(certificate, x509.BasicConstraints)
    certificate_policies = extension_value(certificate, x509.CertificatePolicies)
    crl_distribution_points = extension_value(certificate, x509.CRLDistributionPoints)
    authority_information_access = extension_value(certificate, x509.AuthorityInformationAccess)
    tls_feature = extension_value(certificate, x509.TLSFeature)
    features: dict[str, Any] = {
        "certificate_extension_count": len(certificate.extensions),
        "issuer_attribute_count": len(certificate.issuer),
        "public_key_size": public_key_size,
        "has_basic_constraints": int(basic_constraints is not None),
        "basic_constraints_ca": int(bool(basic_constraints and basic_constraints.ca)),
        "has_authority_key_identifier": int(extension_value(certificate, x509.AuthorityKeyIdentifier) is not None),
        "has_subject_key_identifier": int(extension_value(certificate, x509.SubjectKeyIdentifier) is not None),
        "has_certificate_policies": int(certificate_policies is not None),
        "certificate_policy_count": len(certificate_policies) if certificate_policies is not None else 0,
        "has_crl_distribution_points": int(crl_distribution_points is not None),
        "crl_distribution_point_count": len(crl_distribution_points) if crl_distribution_points is not None else 0,
        "has_authority_information_access": int(authority_information_access is not None),
        "aia_ocsp_count": 0,
        "aia_ca_issuers_count": 0,
        "has_tls_feature": int(tls_feature is not None),
        "tls_feature_count": len(tls_feature) if tls_feature is not None else 0,
        "has_name_constraints": int(extension_value(certificate, x509.NameConstraints) is not None),
        "certificate_version": certificate.version.name.lower(),
        "public_key_algorithm": public_key_algorithm,
        "signature_hash_algorithm": signature_hash_algorithm,
        "signature_algorithm_family": signature_algorithm_family,
        "issuer_organization": name_attribute(certificate.issuer, NameOID.ORGANIZATION_NAME),
        "issuer_country": name_attribute(certificate.issuer, NameOID.COUNTRY_NAME),
    }
    if authority_information_access is not None:
        features["aia_ocsp_count"] = sum(
            item.access_method == AuthorityInformationAccessOID.OCSP for item in authority_information_access
        )
        features["aia_ca_issuers_count"] = sum(
            item.access_method == AuthorityInformationAccessOID.CA_ISSUERS for item in authority_information_access
        )
    features.update(key_usage_flags(extension_value(certificate, x509.KeyUsage)))
    features.update(extended_key_usage_flags(extension_value(certificate, x509.ExtendedKeyUsage)))
    features.update(san_structure_features(normalized_names))
    missing = set(CERTIFICATE_METADATA_NUMERIC_FIELDS + CERTIFICATE_METADATA_CATEGORICAL_FIELDS).difference(features)
    if missing:
        raise ValueError(f"feature implementation omitted: {sorted(missing)}")
    return features


def output_schema(pa):
    fields = [
        pa.field("hostname", pa.string()),
        pa.field("label", pa.string()),
        pa.field("collection_date", pa.date32()),
        pa.field("ct_timestamp", pa.string()),
        pa.field("certificate_not_before", pa.string()),
        pa.field("certificate_not_after", pa.string()),
        pa.field("issuer", pa.string()),
        pa.field("san_count", pa.int32()),
        pa.field("is_wildcard", pa.bool_()),
        pa.field("certificate_fingerprint", pa.string()),
        pa.field("source_log", pa.string()),
        pa.field("source_archive", pa.string()),
        pa.field("log_entry_id", pa.int64()),
        pa.field("entry_type", pa.string()),
        pa.field("hostname_length", pa.int32()),
        pa.field("digit_count", pa.int32()),
        pa.field("hyphen_count", pa.int32()),
        pa.field("character_entropy", pa.float64()),
        pa.field("subdomain_depth", pa.int32()),
        pa.field("metadata_schema_version", pa.string()),
    ]
    fields.extend(pa.field(name, pa.float64()) for name in CERTIFICATE_METADATA_NUMERIC_FIELDS)
    fields.extend(pa.field(name, pa.string()) for name in CERTIFICATE_METADATA_CATEGORICAL_FIELDS)
    return pa.schema(fields)


def main() -> int:
    args = parse_args()
    if args.window_days < 1:
        raise SystemExit("--window-days must be positive")
    if not args.archive.is_file():
        raise SystemExit(f"archive does not exist: {args.archive}")
    if not args.labels.is_file():
        raise SystemExit(f"labels do not exist: {args.labels}")
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ModuleNotFoundError as exc:
        raise SystemExit("pyarrow is required; install requirements.txt") from exc

    started = time.monotonic()
    labels = load_labels(args.labels)
    schema = output_schema(pa)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.stats.parent.mkdir(parents=True, exist_ok=True)
    scan_stats: Counter[str] = Counter()
    matched_labels: Counter[str] = Counter()
    rows: list[dict[str, object]] = []
    sct_min: int | None = None
    sct_max: int | None = None

    with zipfile.ZipFile(args.archive) as archive, pq.ParquetWriter(args.output, schema=schema, compression="zstd") as writer:
        log_info = json.loads(archive.read("log.v3.json"))
        source_log = str(log_info["url"])
        members = sorted(
            (member for member in archive.infolist() if member.filename.startswith("tile/data/")),
            key=lambda member: data_tile_index(member.filename),
        )
        if args.max_tiles is not None:
            members = members[: args.max_tiles]
        for member_number, member in enumerate(members, start=1):
            tile_index = data_tile_index(member.filename)
            blob = archive.read(member)
            offset = within_tile = 0
            while offset < len(blob):
                entry_index = tile_index * 256 + within_tile
                within_tile += 1
                scan_stats["ct_entries_inspected"] += 1
                try:
                    timestamp_ms, entry_type, certificate_der, offset = read_tile_leaf(blob, offset)
                except ValueError:
                    scan_stats["tile_leaf_parse_failures"] += 1
                    break
                sct_min = timestamp_ms if sct_min is None else min(sct_min, timestamp_ms)
                sct_max = timestamp_ms if sct_max is None else max(sct_max, timestamp_ms)
                try:
                    certificate = x509.load_der_x509_certificate(certificate_der)
                except ValueError:
                    scan_stats["certificate_parse_failures"] += 1
                    continue
                scan_stats["certificates_parsed"] += 1
                try:
                    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    scan_stats["certificates_without_dns_san"] += 1
                    continue
                except ValueError:
                    scan_stats["malformed_certificate_extensions"] += 1
                    continue
                normalized_names: list[str] = []
                for name in names:
                    try:
                        normalized = normalise_hostname(name)
                    except (UnicodeError, ValueError):
                        scan_stats["invalid_dns_san"] += 1
                        continue
                    if normalized not in normalized_names:
                        normalized_names.append(normalized)
                scan_stats["dns_sans_inspected"] += len(normalized_names)
                candidates = [name for name in normalized_names if not name.startswith("*.") and name in labels]
                if not candidates:
                    continue
                try:
                    rich_features = certificate_metadata_features(certificate, normalized_names)
                except (TypeError, ValueError, UnsupportedAlgorithm):
                    scan_stats["certificate_metadata_feature_failures"] += 1
                    continue
                sct_time = dt.datetime.fromtimestamp(timestamp_ms / 1000, dt.UTC)
                fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
                for hostname in candidates:
                    lexical_features = hostname_features(hostname)
                    for label, collection_date in labels[hostname]:
                        day_start = dt.datetime.combine(collection_date, dt.time.min, dt.UTC)
                        if not day_start - dt.timedelta(days=args.window_days) <= sct_time < day_start:
                            continue
                        rows.append(
                            {
                                "hostname": hostname,
                                "label": label,
                                "collection_date": collection_date,
                                "ct_timestamp": iso_utc(timestamp_ms),
                                "certificate_not_before": certificate_time(certificate.not_valid_before),
                                "certificate_not_after": certificate_time(certificate.not_valid_after),
                                "issuer": certificate.issuer.rfc4514_string(),
                                "san_count": len(normalized_names),
                                "is_wildcard": False,
                                "certificate_fingerprint": fingerprint,
                                "source_log": source_log,
                                "source_archive": args.archive.name,
                                "log_entry_id": entry_index,
                                "entry_type": entry_type,
                                "metadata_schema_version": FEATURE_SCHEMA_VERSION,
                                **lexical_features,
                                **rich_features,
                            }
                        )
                        matched_labels[label] += 1
                        scan_stats["temporally_eligible_exact_matches"] += 1
                        if len(rows) >= CHUNK_RECORDS:
                            writer.write_table(pa.Table.from_pylist(rows, schema=schema))
                            rows.clear()
            if member_number % 1024 == 0:
                print(f"progress tiles={member_number}/{len(members)} entries={scan_stats['ct_entries_inspected']}", file=sys.stderr, flush=True)
        if rows:
            writer.write_table(pa.Table.from_pylist(rows, schema=schema))

    summary = {
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "archive": str(args.archive),
        "archive_sha256": sha256_file(args.archive),
        "label_metadata": str(args.labels),
        "label_metadata_sha256": sha256_file(args.labels),
        "metadata_schema_version": FEATURE_SCHEMA_VERSION,
        "numeric_feature_count": len(CERTIFICATE_METADATA_NUMERIC_FIELDS),
        "categorical_feature_count": len(CERTIFICATE_METADATA_CATEGORICAL_FIELDS),
        "window_days": args.window_days,
        "max_tiles": args.max_tiles,
        "candidate_label_hostnames": len(labels),
        "ct_sct_timestamp_min_utc": iso_utc(sct_min) if sct_min is not None else None,
        "ct_sct_timestamp_max_utc": iso_utc(sct_max) if sct_max is not None else None,
        "scan_counts": dict(sorted(scan_stats.items())),
        "matched_label_counts": dict(sorted(matched_labels.items())),
        "output": {"path": str(args.output), "bytes": args.output.stat().st_size, "sha256": sha256_file(args.output)},
        "safety_note": "Restricted exact CT/Phresh matches only. No URL, HTML, target annotation, unmatched CT hostname, raw DNS-SAN list, certificate bytes, serial number, public key, or extension value is emitted. Unmatched CT entries are not assigned a benign label.",
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
    args.stats.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
