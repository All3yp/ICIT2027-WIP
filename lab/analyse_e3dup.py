#!/usr/bin/env python3
"""Explain the E3 duplicate-callback result from the recorded packet-ordering traces.

Reads the per-run `server_trace.jsonl` / `client_trace.jsonl` written by `lab/deep_trace.py` and
reports, for each byte-identical `LRRTT` pair, whether both copies passed the transport packet
filter before the first copy's hash was committed by the inbound worker.

Nothing is inferred that the trace does not contain: every value printed is an event timestamp,
a recorded filter outcome, or a count read from the run's manifest.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

LRRTT_CONTEXT = 0xFE


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def preceding_burst(events: list[dict], index: int) -> int | None:
    """Ordinal of the most recent recv call before `index`, used to group frames per read."""
    for candidate in range(index - 1, -1, -1):
        if events[candidate].get("event") == "recv":
            return candidate
    return None


def match(events: list[dict], start: int, kind: str, packet_hash: str) -> dict | None:
    for event in events[start:]:
        if event.get("event") == kind and event.get("hash") == packet_hash:
            return event
    return None


def analyse_run(run_dir: Path) -> dict:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    server = load_jsonl(run_dir / "server_trace.jsonl")
    client = load_jsonl(run_dir / "client_trace.jsonl")
    callbacks = manifest.get("server_callbacks_by_link") or {}
    calls = max(callbacks.values()) if callbacks else 0

    filters = [(index, event) for index, event in enumerate(server)
               if event.get("event") == "filter" and event.get("context") == LRRTT_CONTEXT]
    copies = []
    for ordinal, (index, event) in enumerate(filters, start=1):
        packet_hash = event["hash"]
        enqueue = match(server, index, "enqueue", packet_hash)
        dequeue = match(server, index, "dequeue", packet_hash)
        inbound = match(server, index, "inbound_entry", packet_hash)
        commit = match(server, index, "hash_add", packet_hash)
        received = match(server, index, "link_receive", packet_hash)
        copies.append({
            "copy": ordinal,
            "filter_ns": event["t_ns"],
            "present_at_filter": event["present"],
            "passed": event["passed"],
            "recv_burst": preceding_burst(server, index),
            "enqueue_ns": enqueue["t_ns"] if enqueue else None,
            "queue_depth_after_enqueue": enqueue.get("queue_depth_after") if enqueue else None,
            "dequeue_ns": dequeue["t_ns"] if dequeue else None,
            "present_at_dispatch": inbound.get("present") if inbound else None,
            "hash_commit_ns": commit["t_ns"] if commit else None,
            "already_present_at_commit": commit.get("already_present") if commit else None,
            "delivered_to_link": received is not None,
            "link_status_at_delivery": received.get("status") if received else None,
        })

    window_us = None
    enqueue_to_commit_us = None
    margin_us = None
    if len(copies) >= 2 and copies[0]["filter_ns"] is not None and copies[0]["hash_commit_ns"] is not None:
        window_us = round((copies[0]["hash_commit_ns"] - copies[0]["filter_ns"]) / 1000.0, 2)
    if len(copies) >= 2 and copies[0]["enqueue_ns"] is not None and copies[0]["hash_commit_ns"] is not None:
        enqueue_to_commit_us = round((copies[0]["hash_commit_ns"] - copies[0]["enqueue_ns"]) / 1000.0, 2)
    if len(copies) >= 2 and copies[0]["enqueue_ns"] is not None:
        margin_us = round((copies[1]["filter_ns"] - copies[0]["enqueue_ns"]) / 1000.0, 2)

    committed_before_second_filter = None
    if len(copies) >= 2 and copies[0]["hash_commit_ns"] is not None:
        committed_before_second_filter = copies[0]["hash_commit_ns"] < copies[1]["filter_ns"]

    same_burst = None
    if len(copies) >= 2 and copies[0]["recv_burst"] is not None:
        same_burst = copies[0]["recv_burst"] == copies[1]["recv_burst"]

    duplicate_lengths = [event for event in (manifest.get("perturbation_events") or [])
                         if event.get("perturbation") == "dup"]
    frame_bytes = duplicate_lengths[0]["bytes"] if duplicate_lengths else None
    transmissions = [event for event in client if event.get("event") == "tx" and event.get("bytes") == frame_bytes]
    send_separation_us = None
    if len(transmissions) >= 2:
        send_separation_us = round((transmissions[1]["t_ns"] - transmissions[0]["t_ns"]) / 1000.0, 2)

    arrival_separation_us = None
    if len(copies) >= 2:
        arrival_separation_us = round((copies[1]["filter_ns"] - copies[0]["filter_ns"]) / 1000.0, 2)

    relay = manifest.get("relay") or {}
    if relay.get("enabled"):
        mechanism = "relay"
        nominal_delay = relay.get("duplicate_delay_seconds")
    elif duplicate_lengths:
        mechanism = "sender"
        nominal_delay = manifest.get("dup_delay")
    else:
        mechanism = "none"
        nominal_delay = None

    return {
        "run": run_dir.name,
        "trial": manifest.get("trial"),
        "status": manifest.get("status"),
        "mechanism": mechanism,
        "sync_inbound": manifest.get("sync_inbound"),
        "nominal_duplicate_delay_s": nominal_delay,
        "callbacks_per_link": calls,
        "lrrtt_frames_observed": len(copies),
        "copies": copies,
        "same_recv_burst": same_burst,
        "filter_and_commit_window_us": window_us,
        "enqueue_to_commit_us": enqueue_to_commit_us,
        "second_filter_margin_us": margin_us,
        "arrival_separation_us": arrival_separation_us,
        "hash_committed_before_second_filter": committed_before_second_filter,
        "measured_send_separation_us": send_separation_us,
        "relay_key_material": False if mechanism == "relay" else None,
    }


def summarise(rows: list[dict]) -> dict:
    rows = [row for row in rows if row["status"] == "OK"]
    grouped: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row["mechanism"], row["nominal_duplicate_delay_s"], bool(row["sync_inbound"]))
        grouped.setdefault(key, []).append(row)

    table = {}
    for (mechanism, delay, sync), members in sorted(
            grouped.items(), key=lambda item: (item[0][0], item[0][1] or 0, item[0][2])):
        label = f"{mechanism}:{delay}{':sync' if sync else ''}"
        table[label] = {
            "mechanism": mechanism,
            "second_copy_delay_seconds": delay,
            "inbound_queue": not sync,
            "n": len(members),
            "callbacks_per_link": [member["callbacks_per_link"] for member in members],
            "two_callbacks": sum(1 for member in members if member["callbacks_per_link"] == 2),
            "same_recv_burst": [member["same_recv_burst"] for member in members],
            "hash_committed_before_second_filter": [
                member["hash_committed_before_second_filter"] for member in members],
            "emission_separation_us": [member["measured_send_separation_us"] for member in members],
            "arrival_separation_us": [member["arrival_separation_us"] for member in members],
            "window_us": [member["filter_and_commit_window_us"] for member in members],
            "enqueue_to_commit_us": [member["enqueue_to_commit_us"] for member in members],
            "margin_us": [member["second_filter_margin_us"] for member in members],
        }
    return table


def compact(table: dict) -> str:
    lines = ["Byte-identical LRRTT copies vs separation (callbacks per link id)",
             f"{'condition':22s} {'n':>2s} {'callbacks':12s} {'commit<2nd_filter':17s} "
             f"{'arrival_sep_us':22s} {'window_us':18s}"]
    for label, row in table.items():
        lines.append(f"{label:22s} {row['n']:2d} {str(row['callbacks_per_link']):12s} "
                     f"{str(row['hash_committed_before_second_filter']):17s} "
                     f"{str(row['arrival_separation_us']):22s} {str(row['window_us']):18s}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Explain the E3 duplicate-callback mechanism from traces")
    parser.add_argument("root", type=Path, help="dataset root containing <trial>_<stamp>_<id>/ dirs")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--per-run", action="store_true", help="print one row per run")
    args = parser.parse_args()

    rows = [analyse_run(path.parent) for path in sorted(args.root.glob("*/manifest.json"))]
    table = summarise(rows)
    print(compact(table))
    if args.per_run:
        for row in rows:
            if row["status"] != "OK":
                print(f"  {row['run']}: status {row['status']}")
                continue
            print(f"  {row['run']}: cb={row['callbacks_per_link']} burst={row['same_recv_burst']} "
                  f"commit_first={row['hash_committed_before_second_filter']} "
                  f"sep={row['measured_send_separation_us']}us window={row['filter_and_commit_window_us']}us")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({"conditions": table, "runs": rows}, indent=2) + "\n",
                                 encoding="utf-8")


if __name__ == "__main__":
    main()
