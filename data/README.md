# Reproducing the CT/PhreshPhish dataset

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
