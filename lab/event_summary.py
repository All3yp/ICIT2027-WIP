#!/usr/bin/env python3
"""Read real lab JSONL traces and count destination callbacks per link."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("event_files", nargs="+", type=Path)
    args = parser.parse_args()
    by_link = Counter()
    by_event = Counter()
    by_run = Counter()
    for path in args.event_files:
        with path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                item = json.loads(line)
                by_event[item["event"]] += 1
                by_run[item["run_id"]] += 1
                if item["event"] == "server_established":
                    by_link[(str(path), item["run_id"], item["link_id"])] += 1
    print(json.dumps({
        "source_files": [str(p) for p in args.event_files],
        "event_counts": dict(by_event),
        "server_callbacks_by_file_run_link": [{"file": file, "run_id": run, "link_id": lid, "callbacks": count}
            for (file, run, lid), count in sorted(by_link.items())],
        "runs_observed": len(by_run),
        "interpretation": "Descriptive counts only. No security conclusion without validating source version, packet delivery, transport filters and application consequence.",
    }, indent=2))


if __name__ == "__main__":
    main()
