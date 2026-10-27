# E3dup mechanism dataset (2026-10-23)

Purpose: explain *why* two byte-identical `LRRTT` frames trigger two responder callbacks when
they arrive together, and bound the arrival separation at which they stop doing so. This is a
separate dataset from `results/trials/` (which stays exactly as reported: 165 executed / 159 `OK`).

## Runs

54 runs, all status `OK`, one fresh process pair (or process triple, for the relay conditions)
per run, RNS 1.5.7, loopback TCP only.

| Trial | mechanism | second copy after | runs | callbacks per `link_id` |
|---|---|---|---|---|
| `E3dupQ0` | sender-side duplicate | 0 s (one transmit call) | 6 | 2 (6/6) |
| `E3dupQ1ms` | sender-side duplicate | 1 ms | 6 | 1 (6/6) |
| `E3dupQ5ms` | sender-side duplicate | 5 ms | 6 | 1 (6/6) |
| `E3dupQ20ms` | sender-side duplicate | 20 ms | 6 | 1 (6/6) |
| `E3dupQ300ms` | sender-side duplicate | 300 ms | 6 | 1 (6/6) |
| `E3dupSync0` | sender-side duplicate | 0 s, inbound queue disabled | 6 | 1 (6/6) |
| `M2dup0` | key-less on-path relay | immediate, one write | 6 | 2 (6/6) |
| `M2dup1ms` | key-less on-path relay | nominal 1 ms | 6 | 1 (6/6) |
| `M2dup20ms` | key-less on-path relay | nominal 20 ms | 6 | 1 (6/6) |

`E3dupSync0` is the mechanism control: `Transport.USE_INBOUND_QUEUE = False` makes the packet
filter and the hash commit happen on the same thread with no queue in between. The relay
conditions use `lab/relay.py`, which imports no RNS code, holds no key and re-emits opaque HDLC
frames; its own log records `key_material_used: false`.

For the relayed delayed conditions the *nominal* 1 ms / 20 ms is not the arrival separation:
TCP delivers the two small writes together, so the measured receiver-side separation is
40.3-41.1 ms. The analyser reports measured arrival separation, not the nominal value.

## Reproduction

```
uv run python lab/run_trial.py --trial E3dupQ0     --repeats 6 --probe-mode none --perturb dup --dup-delay 0.0   --trace-packets --base-port 44200 --outdir results/e3dup
uv run python lab/run_trial.py --trial E3dupQ1ms   --repeats 6 --probe-mode none --perturb dup --dup-delay 0.001 --trace-packets --base-port 44220 --outdir results/e3dup
uv run python lab/run_trial.py --trial E3dupQ5ms   --repeats 6 --probe-mode none --perturb dup --dup-delay 0.005 --trace-packets --base-port 44240 --outdir results/e3dup
uv run python lab/run_trial.py --trial E3dupQ20ms  --repeats 6 --probe-mode none --perturb dup --dup-delay 0.02  --trace-packets --base-port 44260 --outdir results/e3dup
uv run python lab/run_trial.py --trial E3dupQ300ms --repeats 6 --probe-mode none --perturb dup --dup-delay 0.3   --trace-packets --base-port 44280 --outdir results/e3dup
uv run python lab/run_trial.py --trial E3dupSync0  --repeats 6 --probe-mode none --perturb dup --dup-delay 0.0   --trace-packets --sync-inbound --base-port 44300 --outdir results/e3dup
uv run python lab/run_trial.py --trial M2dup0      --repeats 6 --probe-mode none --relay --relay-dup-delay 0.0   --trace-packets --base-port 44500 --outdir results/e3dup
uv run python lab/run_trial.py --trial M2dup1ms    --repeats 6 --probe-mode none --relay --relay-dup-delay 0.001 --trace-packets --base-port 44520 --outdir results/e3dup
uv run python lab/run_trial.py --trial M2dup20ms   --repeats 6 --probe-mode none --relay --relay-dup-delay 0.02  --trace-packets --base-port 44540 --outdir results/e3dup
uv run python lab/analyse_e3dup.py results/e3dup --json-out results/e3dup/summary_e3dup.json
```

## Files per run

`manifest.json`, `server.jsonl`, `client.jsonl`, `server_trace.jsonl`, `client_trace.jsonl`,
`relay.jsonl` (relay conditions only), plus stdout logs and per-run configs.

`server_trace.jsonl` is written by `lab/deep_trace.py`: `recv`, `filter`, `enqueue`, `dequeue`,
`inbound_entry`, `hash_add`, `link_receive`, `rtt_enter`, `rtt_exit`, each with a monotonic
nanosecond timestamp.

## Harness revision note

The traces in this dataset were produced by the `lab/deep_trace.py` revision whose SHA-256 is
recorded in each manifest (`fingerprints.deep_trace_sha256`). That revision wrote the wall-clock
anchor line at the end of the file; the current revision writes it at the start. No record site,
timestamp source or filter decision changed, and the analyser does not read the anchor line.
