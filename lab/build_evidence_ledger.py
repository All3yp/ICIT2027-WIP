#!/usr/bin/env python3
"""Build run-level audit tables from the retained WIP manifests and event logs."""
from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "audit"
DATASETS = (
    ("main", ROOT / "results" / "trials"),
    ("mechanism", ROOT / "results" / "e3dup"),
)
FINGERPRINT_FIELDS = (
    "rns_sdist_sha256",
    "installed_link_py_sha256",
    "link_lab_sha256",
    "deep_trace_sha256",
    "relay_sha256",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def first_event(events: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next((event for event in events if event.get("event") == name), {})


def elapsed_seconds(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    return round(
        (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds(),
        6,
    )


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"No rows available for {path.name}")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def build_run_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    timelines: list[dict[str, Any]] = []

    for dataset_name, dataset_dir in DATASETS:
        manifests = sorted(dataset_dir.glob("*/manifest.json"))
        if not manifests:
            raise FileNotFoundError(f"No manifests found under {dataset_dir}")

        for manifest_path in manifests:
            manifest = load_json(manifest_path)
            trial = manifest.get("trial", "")
            status = manifest.get("status", "UNKNOWN")
            is_smoke = "smoke" in trial.lower()
            included = status == "OK" and not is_smoke
            decision = (
                "reported-condition" if included else
                "preliminary-smoke" if is_smoke and status == "OK" else
                f"non-OK:{status}"
            )
            fingerprints = manifest.get("fingerprints") or {}
            relative_manifest = manifest_path.relative_to(ROOT).as_posix()
            server_path = manifest_path.parent / "server.jsonl"
            client_path = manifest_path.parent / "client.jsonl"
            rows.append({
                "dataset": dataset_name,
                "run_id": manifest_path.parent.name,
                "trial": trial,
                "status": status,
                "included_in_condition_analysis": included,
                "decision_reason": decision,
                "started_utc": manifest.get("started_utc"),
                "finished_utc": manifest.get("finished_utc"),
                "repeat_index": manifest.get("repeat_index"),
                "probe_mode": manifest.get("probe_mode"),
                "probe_delay_s": manifest.get("probe_delay"),
                "supplied_rtt_s": manifest.get("extra_rtt"),
                "guard": manifest.get("hardening"),
                "perturb": manifest.get("perturb"),
                "dup_delay_s": manifest.get("dup_delay"),
                "sync_inbound": manifest.get("sync_inbound"),
                "trace_packets": manifest.get("trace_packets"),
                "pause_seconds": manifest.get("pause_seconds"),
                "observe_seconds": manifest.get("observe_seconds"),
                "callbacks": manifest.get("server_established_count"),
                "stale_s": manifest.get("time_to_stale_seconds"),
                "closed_s": manifest.get("time_to_closed_seconds"),
                "python": manifest.get("python"),
                "kernel": manifest.get("kernel"),
                "interpreter_recorded": manifest.get("interpreter"),
                "rns_sdist_sha256": fingerprints.get("rns_sdist_sha256"),
                "installed_link_py_sha256": fingerprints.get("installed_link_py_sha256"),
                "link_lab_sha256": fingerprints.get("link_lab_sha256"),
                "deep_trace_sha256": fingerprints.get("deep_trace_sha256"),
                "relay_sha256": fingerprints.get("relay_sha256"),
                "manifest_path": relative_manifest,
                "server_log_path": server_path.relative_to(ROOT).as_posix(),
                "client_log_path": client_path.relative_to(ROOT).as_posix(),
            })

            if not trial.startswith("E2"):
                continue

            client_events = load_events(client_path)
            server_events = load_events(server_path)
            client_established = first_event(client_events, "client_established")
            probe_sent = first_event(client_events, "fresh_lrrtt_probe_sent")
            pause_ready = first_event(client_events, "client_ready_for_pause")
            established = [
                event for event in server_events
                if event.get("event") == "server_established"
            ]
            states = {
                name: next((event for event in server_events
                            if event.get("event") == "server_status"
                            and event.get("status_name") == name), {})
                for name in ("STALE", "CLOSED")
            }
            first_callback = established[0] if established else {}
            assigned_rtt_event = established[1] if len(established) > 1 else {}
            timelines.append({
                "run_id": manifest_path.parent.name,
                "trial": trial,
                "status": status,
                "included": included,
                "client_established_utc": client_established.get("timestamp_utc"),
                "server_first_callback_utc": first_callback.get("timestamp_utc"),
                "probe_sent_utc": probe_sent.get("timestamp_utc"),
                "probe_sent_after_client_established_s": elapsed_seconds(
                    client_established.get("timestamp_utc"),
                    probe_sent.get("timestamp_utc"),
                ),
                "requested_probe_delay_s": manifest.get("probe_delay"),
                "supplied_rtt_s": probe_sent.get("supplied_rtt", manifest.get("extra_rtt")),
                "assigned_rtt_s": assigned_rtt_event.get("rtt"),
                "second_callback_utc": assigned_rtt_event.get("timestamp_utc"),
                "request_age_at_probe_s": "NOT_RECORDED",
                "pause_ready_utc": pause_ready.get("timestamp_utc"),
                "actual_sigstop_utc": "NOT_RECORDED",
                "stale_utc": states["STALE"].get("timestamp_utc"),
                "closed_utc": states["CLOSED"].get("timestamp_utc"),
                "stale_since_first_callback_s": manifest.get("time_to_stale_seconds"),
                "closed_since_first_callback_s": manifest.get("time_to_closed_seconds"),
                "stale_since_pause_s": "NOT_MEASURABLE",
                "closed_since_pause_s": "NOT_MEASURABLE",
                "teardown_reasons": ",".join(manifest.get("server_teardown_names") or []),
                "manifest_path": relative_manifest,
            })

    return rows, timelines


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(
        (row["dataset"], row["status"], row["decision_reason"])
        for row in rows
    )
    fingerprints = {
        field: sorted({row[field] for row in rows if row[field]})
        for field in FINGERPRINT_FIELDS
    }
    return {
        "total": len(rows),
        "main": sum(row["dataset"] == "main" for row in rows),
        "mechanism": sum(row["dataset"] == "mechanism" for row in rows),
        "status": dict(Counter(row["status"] for row in rows)),
        "by_decision": [
            {"dataset": key[0], "status": key[1], "decision": key[2], "n": count}
            for key, count in sorted(counts.items())
        ],
        "observed_harness_fingerprints": fingerprints,
        "note": (
            "Run inclusion is conditional on OK and non-smoke. All excluded records are retained. "
            "The mechanism dataset is distinct from the main dataset."
        ),
    }


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rows, timelines = build_run_rows()
    write_csv(OUTPUT_DIR / "run_ledger.csv", rows)
    write_csv(OUTPUT_DIR / "e2_timeline.csv", timelines)
    summary = build_summary(rows)
    (OUTPUT_DIR / "accounting.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"total": summary["total"], "by_decision": summary["by_decision"]}, indent=2))


if __name__ == "__main__":
    main()
