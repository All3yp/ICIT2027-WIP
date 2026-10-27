#!/usr/bin/env python3
"""Summarize trial manifests under a trials directory into a compact table.

Reads only the per-run manifest.json files produced by lab/run_trial.py. Emits a
machine-readable JSON summary plus a short human table. No data invention.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_summary(manifest_paths: list[Path], trial: str | None = None) -> dict:
    """Aggregate per-run manifests into rows, per-trial buckets and a summary block."""
    runs = []
    for manifest_path in manifest_paths:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if trial and manifest.get("trial") != trial:
            continue
        runs.append(manifest)

    rows = []
    for m in runs:
        callbacks = m.get("server_callbacks_by_link") or {}
        rows.append({
            "trial": m.get("trial"),
            "run": Path(m["run_dir"]).name,
            "status": m.get("status"),
            "probe_mode": m.get("probe_mode"),
            "hardening": m.get("hardening"),
            "client_active": m.get("client_active_confirmed"),
            "client_cb": m.get("client_callback_count"),
            "server_cb_total": m.get("server_established_count"),
            "server_cb_by_link": callbacks,
            "max_cb_per_link": max(callbacks.values()) if callbacks else 0,
            "correlated": len(m.get("correlated_link_ids") or []),
            "latency_ms": None if m.get("link_latency_seconds") is None
                          else round(m["link_latency_seconds"] * 1000, 3),
            "probe_sent": m.get("probe_sent"),
            "replay_injected": m.get("replay_injected"),
            "hardening_rtt_rejected": m.get("hardening_rtt_rejected"),
            "server_link_closed": m.get("server_link_closed_events"),
            "client_link_closed": m.get("client_link_closed_events"),
            "server_callback_states": m.get("server_callback_states"),
            "server_late_rx": [s.get("rx") for s in (m.get("server_late_samples") or [])],
            "app_mode": m.get("app_mode"),
            "app_callbacks": m.get("app_callbacks"),
            "app_sessions_created": m.get("app_sessions_created"),
            "app_sessions_for_link": m.get("app_sessions_for_link"),
            "app_accounting_units": m.get("app_accounting_units"),
            "app_redundant_calls": m.get("app_redundant_calls"),
            "app_invariant_violations": m.get("app_invariant_violations"),
            "perturb": m.get("perturb"),
            "server_status_transitions": m.get("server_status_transitions"),
            "time_to_stale_seconds": m.get("time_to_stale_seconds"),
            "time_to_closed_seconds": m.get("time_to_closed_seconds"),
            "server_teardown_names": m.get("server_teardown_names"),
            "server_link_data_statuses": m.get("server_link_data_statuses"),
            "destination_link_series": m.get("server_destination_link_series"),
            "failures": m.get("run_failed_events"),
        })

    by_trial: dict[str, dict] = {}
    for r in rows:
        bucket = by_trial.setdefault(r["trial"], {"runs": 0, "max_cb_per_link": {}, "statuses": set(),
                                                  "variants": set()})
        bucket["runs"] += 1
        bucket["statuses"].add(r["status"])
        bucket["variants"].add(f"{r['probe_mode']}/{r['hardening']}")
        key = str(r["max_cb_per_link"])
        bucket["max_cb_per_link"][key] = bucket["max_cb_per_link"].get(key, 0) + 1
    for bucket in by_trial.values():
        bucket["statuses"] = sorted(bucket["statuses"])
        bucket["variants"] = sorted(bucket["variants"])

    return {
        "trial_filter": trial,
        "runs": len(rows),
        "statuses": sorted({r["status"] for r in rows}),
        "by_trial": by_trial,
        "all_correlated_single_callback": all(
            r["correlated"] == 1 and r["max_cb_per_link"] == 1 for r in rows) if rows else None,
        "rows": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("trials_dir", type=Path)
    parser.add_argument("--trial", help="filter by trial label")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    summary = build_summary(sorted(args.trials_dir.glob("*/manifest.json")), trial=args.trial)
    print(json.dumps(summary, indent=2))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
