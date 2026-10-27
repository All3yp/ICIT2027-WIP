# Isolated trial dataset (2026-10-21)

Produced by `lab/run_trial.py` on **RNS 1.5.7**, loopback TCP only, one fresh
server+client process pair per run, one immutable directory per run. These are the only
admissible artifacts for the link-establishment claims.

## Layout

```
results/trials/<TRIAL>_<UTCstamp>_<uuid8>/
    runtime/{server,client}/config   per-run loopback configs
    runtime/server/identity          per-run (fresh) server identity
    destination_hash                 server -> client hash handoff
    server.jsonl / client.jsonl      structured event traces
    server.stdout.log / client.stdout.log
    manifest.json                    versions, fingerprints, outcome, correlation,
                                     callback states, responder late sample
summary_ALL.json                     aggregate over every run
batch_<TRIAL>_<UTCstamp>.json        per-batch rollup
```

## Reproduction

```
uv run python lab/run_trial.py --trial T0       --repeats 5 --probe-mode none      --base-port 42710 --outdir results/trials
uv run python lab/run_trial.py --trial T2       --repeats 5 --probe-mode fresh     --base-port 42720 --outdir results/trials
uv run python lab/run_trial.py --trial T2ctl    --repeats 5 --probe-mode none      --base-port 42725 --outdir results/trials
uv run python lab/run_trial.py --trial T2infl   --repeats 5 --probe-mode inflated  --base-port 42730 --outdir results/trials
uv run python lab/run_trial.py --trial T2replay --repeats 5 --probe-mode replay    --base-port 42740 --outdir results/trials
uv run python lab/run_trial.py --trial T2bad    --repeats 5 --probe-mode corrupt   --base-port 42750 --outdir results/trials
uv run python lab/run_trial.py --trial T2mal    --repeats 5 --probe-mode malformed --base-port 42760 --outdir results/trials
uv run python lab/run_trial.py --trial T0h      --repeats 5 --probe-mode none      --base-port 42770 --outdir results/trials --harden
uv run python lab/run_trial.py --trial T2h      --repeats 5 --probe-mode fresh     --base-port 42780 --outdir results/trials --harden
uv run python lab/summarize_trials.py results/trials --json-out results/trials/summary_ALL.json
uv run pytest lab/test_lab_infra.py
```

`--probe-once` is an alias of `--probe-mode fresh`, so the commands documented in the first
session still reproduce the original runs.

## Result

165 runs executed; 159 completed with status `OK` (152 in the reported conditions, 7 single-run smoke
executions); six aborted runs are retained and excluded. "callbacks" = responder `link_established`
invocations per `link_id`. The phase-1 conditions are below; the E1/E2/E3 conditions added later
(`E1*`, `E2*`, `E3*`) are tabulated by `uv run python lab/analyse_experiments.py . --compact`
and written to `results/experiments_summary.json`.

| Trial | n | extra packet after `ACTIVE` | max callbacks per `link_id` | outcome |
|---|---|---|---|---|
| T0 | 9 | none | 1 (9/9) | clean establishment |
| T2ctl | 5 | none, matched client timing | 1 (5/5) | timing/instrumentation excluded |
| T2 | 15 | one fresh `LRRTT` | **2 (15/15)** | responder callback re-invoked |
| T2i | 5 | one fresh `LRRTT`, responder-state sampling | **2 (5/5)** | re-invocation + state rewrite measured |
| T2infl | 5 | one fresh `LRRTT`, supplied RTT 1e6 s | **2 (5/5)** | timers pinned to their clamps |
| T2replay | 10 | one fresh `LRRTT`, then identical wire bytes re-transmitted | 2 (10/10) | identical replay not delivered |
| T2bad | 5 | one `LRRTT`, one token-HMAC bit flipped | 1 (5/5) | delivered, key check fails, no teardown |
| T2mal | 5 | validly encrypted `LRRTT`, non-msgpack payload | 1 (5/5) | responder tears the link down |
| T0h | 5 | none, guarded responder | 1 (5/5) | fix transparent to normal establishment |
| T2h | 5 | one fresh `LRRTT`, guarded responder | 1 (5/5), 1 rejection/run | fix removes the re-invocation |

All `OK` runs reached `ACTIVE` and carry the same `link_id` on both sides. Loopback
establishment latency 1.1-2.6 ms across conditions. In T2/T2i/T2infl the second responder
callback lands within ~0.4 ms of the client's probe-send event, 1.0006 s after the first.

## Verdict (bounded)

An authenticated initiator that already holds an `ACTIVE` link can send one additional,
freshly-encrypted `LRRTT` and cause the responder to invoke its application
`link_established` callback again for the **same** `link_id`, while also rewriting
responder-side link state (`rtt`, `activated_at`, `expected_hops`, `establishment_rate`,
keepalive/stale timers). Byte-identical replays are dropped before the link, so the trigger
requires re-encryption (threat model M1).

## Harness notes (transparency)

- **Harness defect, disclosed.** A runtime patch was first written against the wrong target
  (`RNS.Link.Link` instead of the class `RNS.Link`), which aborted 5 `T2bad` client processes
  (`CLIENT_FAILED`) and 1 `T2smoke` server start (`SERVER_NOT_READY`). The defect was fixed and
  the affected conditions re-run. All six aborted runs remain in the dataset and are excluded
  from every reported count.
- **Two harness revisions.** The first session's runs (T0 n=6, T2 n=10, T2ctl n=5) predate the
  responder-state sampling and `rx` counters; later runs of the same conditions add those
  fields. Each manifest records the harness `link_lab_sha256`, so the revision of any run is
  recoverable; conditions and measurement logic are unchanged.
- The first T2 batch (`T2_20261021T0454*`) was produced before the `--trial-label` fix: those
  server traces carry `"trial": "T0"` in the log field. The link/time evidence is unaffected.
  Raw logs were **not** rewritten.
- `T0_20261021T045240Z_0f0c7583` (smoke run) predates the `client_active_confirmed` manifest
  field; its `client.jsonl` still shows `status: 2`, `callback_number: 1`.
