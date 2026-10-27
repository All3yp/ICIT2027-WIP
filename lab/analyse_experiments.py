#!/usr/bin/env python3
"""Aggregate the E1/E2/E3 manifests into the study E1/E2/E3 tables.

Reads only per-run `manifest.json` files produced by lab/run_trial.py, excludes runs whose
status is not `OK`, and reports exact counts and ranges - no statistics are invented and no
value is reported without the artifact it came from.

Run: uv run python lab/analyse_experiments.py results/trials --json-out results/experiments_summary.json
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

E1_TRIALS = {
    "E1nc": "non-idempotent handler, single notification",
    "E1np": "non-idempotent handler, duplicate notification",
    "E1ic": "idempotent handler, single notification",
    "E1ip": "idempotent handler, duplicate notification",
}
E2_TRIALS = {
    "E2base": "no probe (default timers)",
    "E2mid": "probe supplying rtt = 0.075 s",
    "E2huge": "probe supplying rtt = 2.0 s",
    "E2guard": "probe supplying rtt = 0.075 s, guarded responder",
}
E3_PAIRS = {
    "dup": ("E3dup", "E3duph"),
    "drop": ("E3drop", "E3droph"),
    "delay": ("E3delay", "E3delayh"),
    "reorder": ("E3reorder", "E3reorderh"),
    "retransmit": ("E3retx", "E3retxh"),
}

# Second copy of the SAME bytes, at increasing separation. 0 s means both copies leave in one
# transmit call (same processing window); 0.02 s and 0.30 s let the receiver process the first
# copy before the second arrives.
DUP_TIMING = {"E3dup": 0.0, "E3dup20ms": 0.02, "E3retx": 0.30}


def load(trials_dir: Path) -> list[dict]:
    manifests = []
    for path in sorted(trials_dir.glob("*/manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["_path"] = str(path.parent.name)
        manifests.append(manifest)
    return manifests


def used(manifests: list[dict], trial: str) -> list[dict]:
    return [m for m in manifests if m.get("trial") == trial and m.get("status") == "OK"]


def counts(runs: list[dict]) -> list[int]:
    return [max((m.get("server_callbacks_by_link") or {"": 0}).values()) for m in runs]


def read_events(run_dir: Path, name: str) -> list[dict]:
    path = run_dir / name
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


STATE_TRIALS = ("T2i", "T2infl", "E2mid", "E2huge")


def summarise_state_rewrite(trials_dir: Path, manifests: list[dict]) -> dict:
    """Per-condition responder state at the legitimate vs the extra establishment notification.

    Read from each run's own `server.jsonl`, because those fields (including
    `establishment_rate`) are recorded per event rather than duplicated in the manifest.
    """
    table = {}
    for trial in STATE_TRIALS:
        runs = used(manifests, trial)
        rows = []
        for manifest in runs:
            run_dir = trials_dir / Path(manifest["_path"])
            callbacks = [e for e in read_events(run_dir, "server.jsonl")
                         if e.get("event") == "server_established"]
            if not callbacks:
                continue
            first = callbacks[0]
            last = callbacks[-1]
            rows.append({
                "callbacks": len(callbacks),
                "rtt_first": first.get("rtt"), "rtt_last": last.get("rtt"),
                "keepalive_first": first.get("keepalive"), "keepalive_last": last.get("keepalive"),
                "stale_time_first": first.get("stale_time"), "stale_time_last": last.get("stale_time"),
                "rate_first": first.get("establishment_rate"), "rate_last": last.get("establishment_rate"),
                "hops_first": first.get("expected_hops"), "hops_last": last.get("expected_hops"),
                "activated_at_first": first.get("activated_at"), "activated_at_last": last.get("activated_at"),
            })
        if rows:
            table[trial] = {
                "n": len(rows),
                "rtt_first": [r["rtt_first"] for r in rows],
                "rtt_last": [r["rtt_last"] for r in rows],
                "keepalive_first": [r["keepalive_first"] for r in rows],
                "keepalive_last": [r["keepalive_last"] for r in rows],
                "stale_time_first": [r["stale_time_first"] for r in rows],
                "stale_time_last": [r["stale_time_last"] for r in rows],
                "rate_first": [r["rate_first"] for r in rows],
                "rate_last": [r["rate_last"] for r in rows],
                "expected_hops": sorted({r["hops_first"] for r in rows} | {r["hops_last"] for r in rows}),
                "activated_at_changed": sum(1 for r in rows
                                            if r["activated_at_first"] != r["activated_at_last"]),
            }
    return table


def summarise_e1(manifests: list[dict]) -> dict:
    table = {}
    for trial, description in E1_TRIALS.items():
        runs = used(manifests, trial)
        table[trial] = {
            "description": description,
            "n": len(runs),
            "callbacks_per_link": counts(runs),
            "sessions_created": [m.get("app_sessions_created") for m in runs],
            "invariant_violations": [m.get("app_invariant_violations") for m in runs],
            "redundant_calls": [m.get("app_redundant_calls") for m in runs],
        }
    return table


def summarise_e2(manifests: list[dict]) -> dict:
    table = {}
    for trial, description in E2_TRIALS.items():
        runs = used(manifests, trial)
        stale = [m["time_to_stale_seconds"] for m in runs if m.get("time_to_stale_seconds") is not None]
        closed = [m["time_to_closed_seconds"] for m in runs if m.get("time_to_closed_seconds") is not None]
        timers = []
        for m in runs:
            states = m.get("server_callback_states") or []
            if states:
                timers.append({"rtt": states[-1].get("rtt"),
                               "keepalive": states[-1].get("keepalive"),
                               "stale_time": states[-1].get("stale_time")})
        table[trial] = {
            "description": description,
            "n": len(runs),
            "window_seconds": runs[0].get("observe_seconds") if runs else None,
            "reached_stale": len(stale),
            "time_to_stale_seconds": stale,
            "time_to_stale_median": round(statistics.median(stale), 3) if stale else None,
            "time_to_closed_seconds": closed,
            "timers_after_probe": timers,
            "teardown_names": sorted({name for m in runs for name in (m.get("server_teardown_names") or [])}),
            "rejected_extra_lrrtt": [m.get("hardening_rtt_rejected") for m in runs],
        }
    return table


def summarise_e3(manifests: list[dict]) -> dict:
    table = {}
    for name, (plain, guarded) in E3_PAIRS.items():
        entry = {}
        for label, trial in (("unmodified", plain), ("guarded", guarded)):
            runs = used(manifests, trial)
            link_data = [e for m in runs for e in (m.get("server_link_data_early") or [])]
            series = [m.get("server_destination_link_series") for m in runs]
            entry[label] = {
                "trial": trial,
                "n": len(runs),
                "callbacks_per_link": counts(runs),
                "rejected_extra_lrrtt": [m.get("hardening_rtt_rejected") for m in runs],
                "client_active": [m.get("client_active_confirmed") for m in runs],
                "client_status_final": [m.get("client_status_final") for m in runs],
                "server_established_total": [m.get("server_established_count") for m in runs],
                "early_link_data": link_data,
                "destination_link_series": series,
                "perturbation_events": [m.get("perturbation_events") for m in runs],
            }
        table[name] = entry
    return table


def summarise_dup_timing(manifests: list[dict]) -> dict:
    """Byte-identical duplication as a function of the separation between the two copies."""
    table = {}
    for trial, delay in DUP_TIMING.items():
        runs = used(manifests, trial)
        if not runs:
            continue
        table[trial] = {
            "second_copy_delay_seconds": delay,
            "n": len(runs),
            "callbacks_per_link": counts(runs),
            "identical_bytes": True,
            "perturbation": [m.get("perturbation_events") for m in runs][0],
        }
    return table


def compact(output: dict) -> str:
    """One-screen view of the numbers the study cites."""
    lines = [f"manifests {output['manifests_seen']} seen / {output['manifests_ok']} OK; "
             f"excluded: {', '.join(output['excluded_non_ok']) or 'none'}"]
    lines.append("\nE1 application handlers (callbacks | sessions | violations | redundant)")
    for trial, row in output["E1"].items():
        lines.append(f"  {trial:9s} n={row['n']} cb={row['callbacks_per_link']} "
                     f"ses={row['sessions_created']} viol={row['invariant_violations']} "
                     f"red={row['redundant_calls']}")
    lines.append("\nE2 inactivity behaviour (n | reached STALE | t->STALE s | t->CLOSED s | teardown)")
    for trial, row in output["E2"].items():
        lines.append(f"  {trial:9s} n={row['n']} window={row['window_seconds']} "
                     f"stale={row['reached_stale']}/{row['n']} "
                     f"t_stale={row['time_to_stale_seconds']} t_closed={row['time_to_closed_seconds']} "
                     f"teardown={row['teardown_names']} rejected={row['rejected_extra_lrrtt']}")
    lines.append("\nE3 perturbations (unmodified cbs | guarded cbs | guarded rejections | client status)")
    for name, entry in output["E3"].items():
        plain, guarded = entry["unmodified"], entry["guarded"]
        lines.append(f"  {name:11s} plain n={plain['n']} cb={plain['callbacks_per_link']} "
                     f"| guarded n={guarded['n']} cb={guarded['callbacks_per_link']} "
                     f"rej={guarded['rejected_extra_lrrtt']} "
                     f"| client={plain['client_status_final']} "
                     f"| early_data={plain['early_link_data']}")
    lines.append("\nDuplication of the SAME bytes vs separation (callbacks per link)")
    for trial, row in output.get("duplication_timing", {}).items():
        lines.append(f"  {trial:11s} delay={row['second_copy_delay_seconds']}s n={row['n']} "
                     f"cb={row['callbacks_per_link']}")
    lines.append("\nState rewrite (legitimate callback -> callback after the extra LRRTT)")
    for trial, row in output["state_rewrite"].items():
        lines.append(f"  {trial:8s} n={row['n']} rtt {row['rtt_first']} -> {row['rtt_last']} "
                     f"keepalive {row['keepalive_first']} -> {row['keepalive_last']} "
                     f"stale {row['stale_time_first']} -> {row['stale_time_last']} "
                     f"rate {row['rate_first']} -> {row['rate_last']} "
                     f"hops {row['expected_hops']} activated_at_changed={row['activated_at_changed']}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("trials_dir", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--compact", action="store_true", help="print a one-screen table instead of full JSON")
    args = parser.parse_args()

    manifests = load(args.trials_dir)
    ok = [m for m in manifests if m.get("status") == "OK"]
    output = {
        "trials_dir": str(args.trials_dir),
        "manifests_seen": len(manifests),
        "manifests_ok": len(ok),
        "excluded_non_ok": sorted({f"{m.get('trial')}:{m.get('status')}" for m in manifests
                                   if m.get("status") != "OK"}),
        "E1": summarise_e1(manifests),
        "E2": summarise_e2(manifests),
        "E3": summarise_e3(manifests),
        "state_rewrite": summarise_state_rewrite(args.trials_dir, manifests),
        "duplication_timing": summarise_dup_timing(manifests),
    }
    print(compact(output) if args.compact else json.dumps(output, indent=2))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
