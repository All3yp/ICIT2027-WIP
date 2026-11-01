# Experimental Audit Bundle

This directory is generated from retained manifests and event logs under
`results/trials/` and `results/e3dup/`. It does not modify source records or
start new experiments.

## Rebuild

Run from `ICIT2027-WIP/`:

```sh
python3 lab/build_evidence_ledger.py
python3 lab/analyse_e3dup.py results/e3dup --json-out results/audit/e3dup_corrected.json
```

The first command writes `accounting.json`, `run_ledger.csv`, and
`e2_timeline.csv`. The second writes the per-run duplicate analysis and
condition summary to `e3dup_corrected.json`.

## Contents

- `accounting.json`: run totals, inclusion decisions, status counts, and observed
  source fingerprints.
- `run_ledger.csv`: one row per main or mechanism run, including excluded runs.
- `e2_timeline.csv`: recorded E2 events and explicit markers for timestamps not
  present in the historical logs.
- `e3dup_corrected.json`: per-run trace analysis. `filter_and_commit_window_us`
  measures recorded filter-to-hash-commit time;
  `enqueue_to_commit_us` is a distinct metric.

Main and mechanism datasets are accounted separately. Main-condition inclusion
requires status `OK` and a non-smoke trial; excluded records remain in the
ledger. The mechanism campaign is a separate 54-run dataset and is not added to
the main-condition denominator.

The audit contains recorded interpreter paths and run-relative log paths.
Review and redact machine-local details before external publication. This is a
local reproducibility bundle, not a public archive or independent replication.
