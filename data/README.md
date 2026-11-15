# CT/PhreshPhish dataset guide

Each row is a labeled hostname observed in PhreshPhish on `collection_date`
and exactly matched to a DNS subject-alternative name (SAN) in a Certificate
Transparency (CT) certificate. The matched certificate's signed certificate
timestamp (SCT) must be in the 30 days before that UTC collection date.
Unmatched CT names are never assumed to be benign. Within a cohort, the
pipeline retains one eligible observation per non-conflicted hostname/label:
the earliest label day and the most recent eligible SCT on that day.

All releases use the same 64-column schema. Dates and timestamps are UTC ISO
strings; Boolean certificate fields are serialized as `0`/`1`; optional
certificate metadata is blank when unavailable. Raw URLs, webpages,
target-brand labels, certificate bytes, public keys, serial numbers, raw DNS
SAN lists, and extension values are deliberately excluded.

## Column reference

### Dataset identity and label

| Column | Meaning |
| --- | --- |
| `record_id` | Stable hash-derived identifier for this retained hostname/certificate observation. Use only as an identifier, never as a model feature. |
| `dataset_split` | Chronological `train`, `validation`, or `test` partition assigned from `collection_date`. It is cohort-local in the combined 2024--2025 inventory. |
| `cohort_version` | Versioned identifier for the label period, SCT window, and release from which the row came. |
| `hostname` | Normalized hostname that matched a DNS SAN exactly. It is the hostname representation used for hostname-feature baselines. |
| `label` | Supervised class: `phish` or `benign`, from the restricted PhreshPhish label source. |
| `collection_date` | UTC date on which the hostname's label was collected. |

### CT match, certificate timing, and provenance

| Column | Meaning |
| --- | --- |
| `ct_timestamp` | SCT time for the matched CT log entry; it falls within the configured pre-collection window. |
| `certificate_not_before`, `certificate_not_after` | X.509 certificate validity interval. |
| `certificate_fingerprint` | SHA-256 fingerprint of the matched leaf certificate. It supports duplicate and cross-split leakage audits, not hostname modeling. |
| `source_log` | CT log endpoint from which the matching entry was obtained. |
| `source_archive` | CTArchive shard containing that log entry. |
| `log_entry_id` | Entry position/identifier within the source log data. |
| `entry_type` | CT entry form, such as a regular certificate or pre-certificate entry. |

### Hostname and SAN-derived summaries

These fields retain aggregate characteristics while excluding the raw DNS SAN
list. `san_*` fields describe all DNS SANs on the matched certificate; the
unprefixed hostname fields describe only `hostname`.

| Column(s) | Meaning |
| --- | --- |
| `issuer` | Issuer distinguished-name string from the matched certificate. |
| `san_count` | Number of DNS SANs on the certificate. |
| `is_wildcard` | Whether the matched hostname is a wildcard name. |
| `hostname_length`, `digit_count`, `hyphen_count` | Length of the matched hostname and counts of digits and hyphens in it. |
| `character_entropy` | Character-distribution entropy of the matched hostname. |
| `subdomain_depth` | Approximate subdomain depth: hostname label count minus its final two labels, with a minimum of zero. |
| `san_wildcard_count`, `san_idna_count` | Counts of wildcard and IDNA/Punycode DNS SANs, respectively. |
| `san_distinct_final_label_count` | Count of distinct rightmost DNS labels among the certificate's SANs. |
| `san_max_length`, `san_mean_length` | Maximum and mean DNS-SAN hostname length. |
| `san_max_subdomain_depth`, `san_mean_subdomain_depth` | Maximum and mean DNS-SAN subdomain depth. |
| `san_max_entropy`, `san_mean_entropy` | Maximum and mean character entropy across DNS SANs. |

### Certificate structure, key, and extension metadata

| Column(s) | Meaning |
| --- | --- |
| `metadata_schema_version` | Version of the certificate-metadata extraction schema. |
| `certificate_extension_count` | Number of X.509 extensions present. |
| `issuer_attribute_count` | Number of attributes in the issuer distinguished name. |
| `public_key_size` | Size of the subject public key, in bits when reported by the parser. |
| `certificate_version` | X.509 certificate version. |
| `public_key_algorithm` | Reported public-key algorithm family. |
| `signature_hash_algorithm` | Hash/digest algorithm reported for the certificate signature. |
| `signature_algorithm_family` | Normalized signature algorithm family. |
| `issuer_organization`, `issuer_country` | Organization and country attributes, when present in the issuer distinguished name. |
| `has_basic_constraints`, `basic_constraints_ca` | Presence of Basic Constraints and whether it marks the certificate as a CA. |
| `has_key_usage`, `key_usage_digital_signature`, `key_usage_key_encipherment`, `key_usage_key_agreement` | Presence of Key Usage and the corresponding usage flags. |
| `has_extended_key_usage`, `extended_key_usage_count` | Presence and count of Extended Key Usage values. |
| `eku_server_auth`, `eku_client_auth`, `eku_code_signing` | Whether the Extended Key Usage set includes the listed purpose. |
| `has_authority_key_identifier`, `has_subject_key_identifier` | Presence of the corresponding key-identifier extensions. |
| `has_certificate_policies`, `certificate_policy_count` | Presence and count of Certificate Policies values. |
| `has_crl_distribution_points`, `crl_distribution_point_count` | Presence and count of CRL Distribution Points. |
| `has_authority_information_access`, `aia_ocsp_count`, `aia_ca_issuers_count` | Presence of Authority Information Access and counts of OCSP and CA Issuers references. |
| `has_tls_feature`, `tls_feature_count` | Presence and count of TLS Feature extension values. |
| `has_name_constraints` | Whether the Name Constraints extension is present. |

### Using the columns safely

Use `dataset_split` to select the documented evaluation partition and do not
fit models on `record_id`. `cohort_version`, certificate fingerprints, archive
identifiers, log entry IDs, and source fields are provenance/audit fields;
they should not be used as predictive features. For the combined release,
create a new chronological split and redo the certificate-fingerprint and PSL
registrable-domain leakage audit before treating both years as one evaluation
cohort.

## Reproducing the CT/PhreshPhish dataset

This directory contains the end-to-end, resumable reconstruction pipeline for
the checkpoint dataset. It downloads the pinned PhreshPhish labels and the
configured CTArchive releases, applies the temporal exact-DNS-SAN match,
deduplicates records, purges certificate/domain leakage across chronological
splits, and writes the fixed 64-column CSV. Unmatched CT names are never
treated as benign.

## Included final release

`releases/ct_phishing_records_final_v1.csv` is the final audited dataset for
this project. It has 15,518 rows and 64 columns: 12,375 benign and 3,143
phishing examples. Its chronological train/validation/test split contains no
cross-split certificate-fingerprint or PSL registrable-domain groups. The
companion manifest records the input and output checksums, schema, and
split-by-label counts. This is the dataset to use for the project's final
experiments.

Like the preliminary release, it contains labeled hostnames for reproducible
hostname feature experiments, but excludes raw URLs, HTML, target-brand
annotations, certificate bytes, public keys, serial numbers, raw DNS-SAN
lists, and extension values.

## Combined 2024--2025 data inventory

`releases/ct_phishing_records_combined_2024_2025_v1.csv` is a lossless
concatenation of the finalized 2024 and 2025 releases: 25,502 rows in the same
64-column schema (20,864 benign and 4,638 phishing). Its companion manifest
pins both input checksums and the combined output checksum. `cohort_version`
identifies the source cohort for every row.

The retained `dataset_split` value is local to its source cohort; this file is
an all-rows data inventory, not a new globally chronological evaluation set.
Before using both periods in one model evaluation, create a new temporal split
and repeat the certificate-fingerprint and PSL registrable-domain leakage
audit across the complete combined cohort.

## Included preliminary release

`releases/ct_phishing_trustasia_ab_v2.csv` is the frozen preliminary dataset
used for the project's exploratory benchmark: 7,010 post-deduplication,
post-leakage-purge rows (5,848 benign; 1,162 phishing) with 64 columns. Its
companion manifest records the exact input checksum, output checksum, schema,
and split-by-label counts. This is an exploratory benchmark retained for
comparison; use the final release above for the project results.

## Quick start

Run these commands from this `data/` directory. Use restricted storage outside
the repository: the raw PhreshPhish source contains URLs and the process may
temporarily hold a CT ZIP while it is being processed.

```bash
python3 -m venv /tmp/ct-phish-venv
/tmp/ct-phish-venv/bin/pip install -r requirements.txt

/tmp/ct-phish-venv/bin/python recreate_checkpoint_dataset.py \
  --work-directory /mnt/ml-data/ct_phishing_reproduction
```

The default checkpoint profile uses PhreshPhish revision
`eca603e0ecd4f698f8d4d226c088659e72681239`, label days 2025-09-05 through
2025-11-05 UTC, a 30-day pre-collection SCT window, TrustAsia Log2025A/B
shards 017--024, and Sectigo Elephant 2025H2 shards 039--072. Inspect this
configuration without downloading anything:

```bash
/tmp/ct-phish-venv/bin/python recreate_checkpoint_dataset.py --dry-run
```

The clean release is written to
`<work-directory>/release/ct_phishing_records.csv`. Its adjacent JSON manifest
records the schema, split counts, source inputs, and checksums;
`reproduction_manifest.json` records the entire resolved run.

To create a different cohort, supply `--label-start-date`, `--label-end-date`,
and `--window-days` with a new `--work-directory` and `--cohort-version`.
Use repeatable `--ct-source 'TAG|ARCHIVE_ID|LOG_URL|FIRST_SHARD|LAST_SHARD'`
options only after confirming that the selected shards cover the new period.

## Time and storage acknowledgement

This is a long-running data collection job, not a quick download. The default
profile processes 50 CTArchive shards sequentially; individual compressed
archives are commonly about 10--15 GB. In the observed collection environment,
per-shard completion has ranged from under an hour to roughly 12 hours as
network and archive-server conditions vary. Budget several days to a few weeks
for the full profile, keep the process running unattended, and use a stable
network connection. The pipeline resumes completed derived files and partial
downloads; by default it removes each raw CT ZIP only after that shard has been
processed successfully. A 150 GB working volume is suitable for the default
sequential mode, but retaining raw archives with `--keep-raw` requires much
more space.
