# Convenience targets. Each maps to a command documented in README.md.
.PHONY: sync fetch verify-source reproduce analyse figure test verify

PY := uv run python

sync:
	uv sync

fetch:
	sh scripts/fetch_source.sh

verify-source:
	$(PY) lab/audit_release.py artifacts/rns-1.5.7.tar.gz

# Minimal reproduction of the phase-1 conditions (one batch, five runs each).
reproduce:
	$(PY) lab/run_trial.py --trial T0     --repeats 5 --probe-mode none     --base-port 42710 --outdir results/trials
	$(PY) lab/run_trial.py --trial T2ctl  --repeats 5 --probe-mode none     --base-port 42725 --outdir results/trials
	$(PY) lab/run_trial.py --trial T2     --repeats 5 --probe-mode fresh    --base-port 42720 --outdir results/trials
	$(PY) lab/run_trial.py --trial T2infl --repeats 5 --probe-mode inflated --base-port 42730 --outdir results/trials
	$(PY) lab/run_trial.py --trial T2h    --repeats 5 --probe-mode fresh    --base-port 42780 --outdir results/trials --harden

analyse:
	$(PY) lab/summarize_trials.py results/trials --json-out results/trials/summary_ALL.json
	$(PY) lab/analyse_experiments.py results/trials --compact --json-out results/experiments_summary.json
	$(PY) lab/analyse_e3dup.py results/e3dup --json-out results/e3dup/summary_e3dup.json
	$(PY) lab/analyse_multinode.py results/multinode --json-out results/multinode/summary_multinode.json

figure:
	uv run --with matplotlib python lab/make_figures.py --outdir figures

test:
	$(PY) -m pytest lab/test_lab_infra.py lab/test_multinode_infra.py

verify: verify-source test analyse
