#!/usr/bin/env python3
"""Summarise the multi-node feasibility runs: honest-node outcomes inside the adversary window.

The analysis window is derived uniformly from each run's manifest (`started_utc` + the configured
start delay and window), so baseline and adversarial conditions are compared over the same
relative interval. The adversary's own first/last send times are reported separately so the
alignment can be checked rather than assumed.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import statistics
from pathlib import Path

HONEST_NODES = ("h2", "h3")


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def analyse_run(run_dir: Path) -> dict:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    adversary = load(run_dir / "adversary.jsonl")
    started = next((event for event in adversary if event.get("event") == "adversary_started"), None)
    finished_event = next((event for event in adversary
                           if event.get("event") == "adversary_finished"), None)

    if started and finished_event:
        window_start = parse(started["window_started_utc"]).timestamp()
        window_end = parse(finished_event["window_finished_utc"]).timestamp()
        window_source = "adversary_log"
    else:
        start = parse(manifest["started_utc"]).timestamp()
        window_start = start + manifest["adversary_start_delay_seconds"]
        window_end = window_start + manifest["adversary_window_seconds"]
        window_source = "manifest"

    rows = {"run": run_dir.name, "condition": manifest["condition"], "nodes": {},
            "window_source": window_source,
            "window_start_utc": datetime.fromtimestamp(window_start).isoformat(),
            "window_end_utc": datetime.fromtimestamp(window_end).isoformat()}
    for node in HONEST_NODES:
        attempts = [event for event in load(run_dir / f"{node}.jsonl")
                    if event.get("event") == "link_attempt"]
        inside = [event for event in attempts
                  if window_start <= parse(event["timestamp_utc"]).timestamp() <= window_end]
        outside = [event for event in attempts if event not in inside]
        for label, group in (("inside", inside), ("outside", outside)):
            latencies = [event["latency_seconds"] for event in group]
            rows["nodes"].setdefault(node, {})[label] = {
                "attempts": len(group),
                "successes": sum(1 for event in group if event["success"]),
                "success_rate": (round(sum(1 for event in group if event["success"]) / len(group), 3)
                                 if group else None),
                "latency_median_ms": round(statistics.median(latencies) * 1000, 2) if latencies else None,
                "latency_p95_ms": round(percentile(latencies, 0.95) * 1000, 2) if latencies else None,
                "latency_max_ms": round(max(latencies) * 1000, 2) if latencies else None,
                "path_lost_events": sum(1 for event in load(run_dir / f"{node}.jsonl")
                                        if event.get("event") == "path_lost"),
            }
        finished = [event for event in load(run_dir / f"{node}.jsonl")
                    if event.get("event") == "measurer_finished"]
        rows["nodes"][node]["rx_packets_total"] = finished[-1]["rx_packets"] if finished else None

    hub_samples = [event for event in load(run_dir / "hub.jsonl")
                   if event.get("event") == "hub_counters"]
    inside_hub = [event for event in hub_samples
                  if window_start <= parse(event["timestamp_utc"]).timestamp() <= window_end]
    rows["hub"] = {
        "samples_inside": len(inside_hub),
        "max_queue_depth": max((event.get("queue_depth") or 0) for event in inside_hub) if inside_hub else None,
        "cpu_seconds_inside": (round(inside_hub[-1]["cpu_seconds"] - inside_hub[0]["cpu_seconds"], 3)
                               if len(inside_hub) > 1 else None),
        "rx_packets_inside": (inside_hub[-1]["rx_packets"] - inside_hub[0]["rx_packets"]
                              if len(inside_hub) > 1 else None),
        "path_table_max": max((event.get("path_table_size") or 0) for event in hub_samples) if hub_samples else None,
    }

    adversary_started = started
    adversary_finished = finished_event
    rows["adversary"] = {
        "mode": adversary_started.get("mode") if adversary_started else None,
        "sent": adversary_finished.get("sent") if adversary_finished else 0,
        "first_send_utc": adversary_started.get("window_started_utc") if adversary_started else None,
        "last_send_utc": adversary_finished.get("window_finished_utc") if adversary_finished else None,
        "cpu_seconds": adversary_finished.get("cpu_seconds") if adversary_finished else None,
    }
    return rows


def summarise(rows: list[dict]) -> dict:
    conditions: dict[str, list[dict]] = {}
    for row in rows:
        conditions.setdefault(row["condition"], []).append(row)

    table = {}
    for condition, members in conditions.items():
        node_rows = []
        for member in members:
            for node, data in member["nodes"].items():
                node_rows.append((node, data["inside"], data["outside"]))
        inside = [entry[1] for entry in node_rows]
        attempts = sum(item["attempts"] for item in inside)
        successes = sum(item["successes"] for item in inside)
        latencies = [item["latency_median_ms"] for item in inside if item["latency_median_ms"]]
        bursts = [item for item in inside]
        table[condition] = {
            "runs": len(members),
            "node_runs": len(inside),
            "attempts_in_window": attempts,
            "successes_in_window": successes,
            "success_rate": round(successes / attempts, 3) if attempts else None,
            "latency_median_ms": round(statistics.median(latencies), 2) if latencies else None,
            "latency_worst_median_ms": max(latencies) if latencies else None,
            "max_latency_ms": max((item["latency_max_ms"] or 0) for item in bursts) if bursts else None,
            "attempts_outside": sum(entry[2]["attempts"] for entry in node_rows),
            "success_rate_outside": (round(sum(entry[2]["successes"] for entry in node_rows)
                                          / max(1, sum(entry[2]["attempts"] for entry in node_rows)), 3)),
            "path_lost_total": sum(entry[2]["path_lost_events"] for entry in node_rows),
            "hub_cpu_seconds_inside": [member["hub"]["cpu_seconds_inside"] for member in members],
            "hub_max_queue_depth": [member["hub"]["max_queue_depth"] for member in members],
            "hub_path_table_max": [member["hub"]["path_table_max"] for member in members],
            "adversary_sent": [member["adversary"]["sent"] for member in members],
        }
    return table


def compact(table: dict) -> str:
    lines = ["Multi-node feasibility: honest-node outcomes inside the adversarial window",
             f"{'condition':10s} {'runs':>4s} {'attempts':>8s} {'succ_in':>8s} {'rate_in':>8s} "
             f"{'med_ms':>8s} {'max_ms':>8s} {'lost':>5s} {'hub_cpu_s':>22s} {'qmax':>10s} "
             f"{'adv_sent':>10s}"]
    for condition, row in table.items():
        lines.append(
            f"{condition:10s} {row['runs']:4d} {row['attempts_in_window']:8d} "
            f"{row['successes_in_window']:8d} {str(row['success_rate']):>8s} "
            f"{str(row['latency_median_ms']):>8s} {str(row['max_latency_ms']):>8s} "
            f"{row['path_lost_total']:5d} {str(row['hub_cpu_seconds_inside']):>22s} "
            f"{str(row['hub_max_queue_depth']):>10s} {str(row['adversary_sent']):>10s}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse the multi-node feasibility runs")
    parser.add_argument("root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--per-run", action="store_true")
    args = parser.parse_args()

    run_dirs = sorted(path for path in args.root.iterdir()
                      if path.is_dir() and (path / "manifest.json").exists())
    rows = [analyse_run(path) for path in run_dirs]
    rows = [row for row in rows
            if json.loads((args.root / row["run"] / "manifest.json").read_text())["status"] == "OK"]
    table = summarise(rows)
    print(compact(table))
    if args.per_run:
        for row in rows:
            inside = {node: data["inside"] for node, data in row["nodes"].items()}
            print(f"  {row['run']}: adv={row['adversary']['mode']} sent={row['adversary']['sent']} "
                  f"inside={inside}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({"conditions": table, "runs": rows}, indent=2) + "\n",
                                 encoding="utf-8")


if __name__ == "__main__":
    main()
