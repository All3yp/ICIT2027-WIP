# Reticulum RNS 1.5.7 — link-establishment measurement lab

A loopback-only laboratory harness for measuring link establishment in the
Reticulum Network Stack (RNS), pinned to release 1.5.7. The repository contains
the experiment harness, the complete set of run artifacts, the analysis scripts
that turn those artifacts into the study's tables, and the pinned upstream
source distribution.

The accompanying paper is not included in this repository.

Scope: RNS 1.5.7 only, two processes on one host over loopback TCP
(`share_instance=no`, `enable_transport=no`, no automatic interfaces, no
containers). No public Reticulum network and no third-party systems are used.

## Contents

| Path | Purpose |
|---|---|
| `lab/` | harness: trial orchestrator, role driver, application handlers, packet perturbation, key-less relay, multi-node topology, and analysis scripts |
| `results/` | run artifacts and analysis output (see `results/README.md`) |
| `artifacts/rns-1.5.7.tar.gz` | pinned upstream source distribution |
| `scripts/fetch_source.sh` | re-download and verify the pinned source |
| `pyproject.toml`, `uv.lock` | Python 3.13 project and locked dependency set |

## Requirements

- Python 3.13 (see `.python-version`)
- `uv` (https://docs.astral.sh/uv/)

## Setup

```
uv sync
```

This creates `.venv` and installs `rns==1.5.7` and the development dependency
`pytest`.

## Pinned source (`artifacts/`)

`artifacts/rns-1.5.7.tar.gz` is the official RNS 1.5.7 source distribution
published on the Python Package Index. The harness does not unpack it; the runs
import the installed `rns` package, and the archive is kept for provenance and
static inspection.

Where it comes from:

- Upstream project: Reticulum Network Stack (`rns`), https://reticulum.network/
- Release page: https://pypi.org/project/rns/1.5.7/ (uploaded 2026-10-05)
- File: https://files.pythonhosted.org/packages/eb/62/ec929e1a614e0d9f5266f816d73a060eb6b0c89f6684e9ef0b7bedcac17d/rns-1.5.7.tar.gz

Recorded digests:

| Artifact | SHA-256 |
|---|---|
| `rns-1.5.7.tar.gz` (sdist) | `2bb48232e0a10b59b2b21b60e76592362210cdabd343d7b97a3bf1aba22dd879` |
| `rns-1.5.7/RNS/Link.py` | `7b2b24c9d12b0f3ecdcf80b4fdee3b8dc5b75b34df51bd8c1c93a0082302d263` |

To re-download the source and verify it:

```
sh scripts/fetch_source.sh
uv run python lab/audit_release.py artifacts/rns-1.5.7.tar.gz
```

`scripts/fetch_source.sh` resolves the sdist URL for `rns==1.5.7` from the PyPI
JSON API, downloads it into `artifacts/`, and aborts if its SHA-256 differs from
the pinned value. `lab/audit_release.py` recomputes the hash and prints a static
(AST) description of the relevant `RNS/Link.py` routines.

## Reproduce the results

Each trial launches a fresh server+client process pair, writes one immutable
directory per run under the output directory, and records JSONL events plus a
`manifest.json` (versions, fingerprints, timing, outcome).

Phase-1 conditions:

```
uv run python lab/run_trial.py --trial T0       --repeats 5 --probe-mode none      --base-port 42710 --outdir results/trials
uv run python lab/run_trial.py --trial T2ctl    --repeats 5 --probe-mode none      --base-port 42725 --outdir results/trials
uv run python lab/run_trial.py --trial T2       --repeats 5 --probe-mode fresh     --base-port 42720 --outdir results/trials
uv run python lab/run_trial.py --trial T2infl   --repeats 5 --probe-mode inflated  --base-port 42730 --outdir results/trials
uv run python lab/run_trial.py --trial T2replay --repeats 5 --probe-mode replay    --base-port 42740 --outdir results/trials
uv run python lab/run_trial.py --trial T2bad    --repeats 5 --probe-mode corrupt   --base-port 42750 --outdir results/trials
uv run python lab/run_trial.py --trial T2mal    --repeats 5 --probe-mode malformed --base-port 42760 --outdir results/trials
uv run python lab/run_trial.py --trial T0h      --repeats 5 --probe-mode none      --base-port 42770 --outdir results/trials --harden
uv run python lab/run_trial.py --trial T2h      --repeats 5 --probe-mode fresh     --base-port 42780 --outdir results/trials --harden
```

Application-impact, inactivity and guard-regression conditions (E1/E2/E3): the
exact commands are listed in `results/trials/README.md`.

Duplicate-window and key-less-relay mechanism conditions: `results/e3dup/README.md`.

Cross-peer multi-node conditions: `results/multinode/README.md`.

Aggregate the runs and rebuild the study's tables and figure:

```
uv run python lab/summarize_trials.py results/trials --json-out results/trials/summary_ALL.json
uv run python lab/analyse_experiments.py results/trials --compact --json-out results/experiments_summary.json
uv run python lab/analyse_e3dup.py results/e3dup --json-out results/e3dup/summary_e3dup.json
uv run python lab/analyse_multinode.py results/multinode --json-out results/multinode/summary_multinode.json
uv run --with matplotlib python lab/make_figures.py --outdir figures
```

The committed `results/` tree is the reference dataset; re-running the commands
regenerates it under the same names. The analysis is deterministic given the
manifests.

## Verify

```
uv run pytest lab/test_lab_infra.py lab/test_multinode_infra.py
```

The tests exercise the harness infrastructure (loopback configs, event logging,
manifest fields, guard installation, relay framing). To confirm that the analysis
reproduces the committed summary, compare the output of

```
uv run python lab/analyse_experiments.py results/trials --compact
```

against `results/experiments_summary.json`.

## Dataset

`results/` holds three datasets plus their analysis output:

- `results/trials/` — 165 runs (159 `OK`), the admissible dataset for the
  link-establishment claims.
- `results/e3dup/` — 54 runs covering the duplicate-filter window and the
  key-less relay (threat model M2).
- `results/multinode/` — 8 runs of the cross-peer feasibility test; the 8
  pre-fix runs are retained separately under `results/multinode_pre_fix_invalid/`
  and are used for no claim.

Regenerable per-run RNS runtime state (identity keys, storage, generated
interfaces) is listed in `.gitignore` and is not part of the dataset.

## License

Code is licensed under the MIT License (`LICENSE`). The datasets under `results/`
are licensed under Creative Commons Attribution 4.0 (`LICENSE-CC-BY-4.0`).

## Citation

See `CITATION.cff`.
