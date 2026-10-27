# Multi-node cross-peer feasibility dataset (2026-10-23)

Question: can one authenticated participant, using protocol-compliant control traffic, degrade
the connectivity of unrelated honest participants despite RNS admission controls?

Topology (all loopback, separate process per node, no containers):

```
H2 (measurer) ─┐
H3 (measurer) ─┼─ TCP ── hub (enable_transport = yes) ── TCP ── H1 (announcer)
A  (adversary)─┘
```

Honest outcome measured independently by H2 and H3: a repeated route lookup plus link
establishment to H1's destination once per second; success, latency and per-process counters are
recorded. The adversary sends protocol-compliant control traffic at 10 packets/s for 12 s, after a
10 s settle period. The analysis window is taken from the adversary's own logged start/finish
times, so honest attempts are split by the actual adversarial interval rather than an assumption.

| Condition | Adversary traffic | Runs |
|---|---|---|
| `baseline` | none | 2 |
| `benign` | path requests for the real honest destination, 10/s | 2 |
| `unknown` | path requests for random 16-byte destination hashes, 10/s | 2 |
| `announce` | announces for fresh synthetic destinations, 10/s | 2 |

## Result (32 attempts per condition per node)

| Condition | Attempts in window | Success | Median latency | Max latency | Hub CPU in window | Max queue depth | Packets sent |
|---|---|---|---|---|---|---|---|
| baseline | 48 | 48 (1.00) | 1.8-2.5 ms | 3.9 ms | 0.022 s | 0 | 0 |
| benign | 48 | 48 (1.00) | 1.6-1.9 ms | 3.4 ms | 0.052-0.055 s | 0 | 120 |
| unknown | 48 | 48 (1.00) | 1.8-2.4 ms | 4.1 ms | 0.039-0.042 s | 0 | 120 |
| announce | 48 | 48 (1.00) | 1.9-2.2 ms | 5.4 ms | 0.053-0.059 s | 0 | 120 |

No delivery failure, no route loss, no queue growth and no path-table growth beyond three entries
were observed at this rate. The only measurable effect is hub CPU time proportional to packet
count (about 0.15-0.26 ms of CPU per control packet), which is the cost of processing, not a
disproportionate or amplified cost. This is a bounded negative result: it does not show that
higher rates, many colluding participants, radio media, or multi-hop transport cannot degrade
honest peers, and it does not test those.

## Reproduction

```
uv run python lab/run_multinode.py --condition baseline --repeats 2 --rate 10 --window 12 --start-delay 10 --duration 30 --path-timeout 15 --connect-stagger 2 --base-port 44700 --outdir results/multinode
uv run python lab/run_multinode.py --condition benign   --repeats 2 --rate 10 --window 12 --start-delay 10 --duration 30 --path-timeout 15 --connect-stagger 2 --base-port 44710 --outdir results/multinode
uv run python lab/run_multinode.py --condition unknown  --repeats 2 --rate 10 --window 12 --start-delay 10 --duration 30 --path-timeout 15 --connect-stagger 2 --base-port 44720 --outdir results/multinode
uv run python lab/run_multinode.py --condition announce --repeats 2 --rate 10 --window 12 --start-delay 10 --duration 30 --path-timeout 15 --connect-stagger 2 --base-port 44730 --outdir results/multinode
uv run python lab/analyse_multinode.py results/multinode --json-out results/multinode/summary_multinode.json
```

## Harness defect found and corrected (runs retained separately)

The first attempt (`results/multinode_pre_fix_invalid/`, 8 runs, all `OK`) had the measurer call
`Transport.request_path()` every 0.5 s while waiting. RNS batches repeat requests for a
destination already being resolved (`Transport.inflight_path_requests`), so route discovery
stalled until the batch timeout and honest nodes lost their path mid-run. That is a harness
artifact, not adversarial impact. The measurer now requests at most once every 5 s
(`PATH_REQUEST_INTERVAL`), after which both honest nodes acquire the path in 0.75 s and complete
every attempt. The pre-fix runs are retained, unmodified, and are not used for any claim.
