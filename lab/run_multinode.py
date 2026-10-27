#!/usr/bin/env python3
"""Bounded, isolated multi-node RNS topology: 3 honest nodes, 1 hub, optional adversary.

Topology (all loopback):

    H2 (measurer) ─┐
    H3 (measurer) ─┼─ TCP ── hub (enable_transport = yes) ── TCP ── H1 (announcer)
    A  (adversary)─┘

Each node is a separate process with its own configuration and storage directory. The adversary
emits protocol-compliant control traffic at a bounded rate for a bounded window; honest nodes
measure independently of it and are later split by that window in analysis. No process is
reused between repeats; no public interface exists in any configuration.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parent
NODE_APP = LAB_DIR / "node_app.py"
SDIST = REPO_ROOT / "artifacts" / "rns-1.5.7.tar.gz"

HUB_CONFIG = """[reticulum]
enable_transport = yes
share_instance = no

[interfaces]
  [[Research Topology Hub]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
"""
SPOKE_CONFIG = """[reticulum]
enable_transport = no
share_instance = no

[interfaces]
  [[Research Topology Spoke]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port}
"""

NODES = ("hub", "h1", "h2", "h3", "adversary")
CONDITIONS = ("baseline", "benign", "unknown", "announce")


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def terminate(process: subprocess.Popen, settle: float = 1.0) -> dict:
    time.sleep(settle)
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
        return {"exit_code": process.returncode, "hard_kill": False}
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        return {"exit_code": process.returncode, "hard_kill": True}


def write_config(directory: Path, template: str, port: int) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "config"
    target.write_text(template.format(port=port), encoding="utf-8")
    return target


def run_repeat(args: argparse.Namespace, index: int) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.outdir / f"{args.condition}_{stamp}_{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    port = args.base_port + index
    if port_open(port):
        (run_dir / "manifest.json").write_text(json.dumps(
            {"condition": args.condition, "status": "ABORTED",
             "reason": f"port {port} already in use"}, indent=2) + "\n", encoding="utf-8")
        return {"run_dir": str(run_dir), "status": "ABORTED_PORT_IN_USE"}

    configs = {name: write_config(run_dir / "runtime" / name, HUB_CONFIG if name == "hub"
                                  else SPOKE_CONFIG, port) for name in NODES}
    target_file = run_dir / "target_hash"
    processes: dict[str, subprocess.Popen] = {}
    logs: dict[str, object] = {}

    def launch(name: str, *extra: str) -> None:
        role = {"h1": "announcer", "h2": "measurer", "h3": "measurer"}.get(name, name)
        logs[name] = (run_dir / f"{name}.stdout.log").open("w", encoding="utf-8")
        cmd = [sys.executable, str(NODE_APP), role,
               "--config", str(run_dir / "runtime" / name),
               "--events", str(run_dir / f"{name}.jsonl"), *extra]
        if args.loglevel is not None:
            cmd += ["--loglevel", str(args.loglevel)]
        processes[name] = subprocess.Popen(cmd, stdout=logs[name], stderr=subprocess.STDOUT,
                                           cwd=str(REPO_ROOT))

    manifest: dict = {
        "condition": args.condition,
        "repeat_index": index,
        "port": port,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "adversary_mode": args.mode if args.condition != "baseline" else None,
        "adversary_rate_hz": args.rate if args.condition != "baseline" else None,
        "adversary_window_seconds": args.window,
        "adversary_start_delay_seconds": args.start_delay,
        "honest_duration_seconds": args.duration,
        "connect_stagger_seconds": args.connect_stagger,
        "path_timeout_seconds": args.path_timeout,
        "fingerprints": {
            "rns_sdist_sha256": sha256_file(SDIST),
            "node_app_sha256": sha256_file(NODE_APP),
            "configs": {name: sha256_file(path) for name, path in configs.items()},
        },
    }

    launch("hub", "--duration", str(args.duration + 15))
    deadline = time.monotonic() + 20
    while not port_open(port) and time.monotonic() < deadline:
        time.sleep(0.2)
    manifest["hub_listening"] = port_open(port)

    # The announcer must outlive every measurer, including their route-discovery phase.
    launch("h1", "--target-out", str(target_file),
           "--duration", str(args.duration + args.path_timeout + 10))
    deadline = time.monotonic() + 20
    while not (target_file.exists() and target_file.read_text().strip()) \
            and time.monotonic() < deadline:
        time.sleep(0.1)
    manifest["announcer_ready"] = target_file.exists()

    mode = "unknown" if args.condition == "baseline" else args.condition
    if args.condition != "baseline":
        launch("adversary", "--mode", mode, "--rate", str(args.rate),
               "--window", str(args.window), "--start-delay", str(args.start_delay),
               "--target-file", str(target_file), "--duration", str(args.duration))

    for name in ("h2", "h3"):
        launch(name, "--target-file", str(target_file), "--duration", str(args.duration),
               "--path-timeout", str(args.path_timeout))
        time.sleep(args.connect_stagger)
    manifest["launched_utc"] = datetime.now(timezone.utc).isoformat()

    results = {}
    deadline = time.monotonic() + args.duration + args.start_delay + 20
    for name, process in processes.items():
        try:
            process.wait(timeout=max(1.0, deadline - time.monotonic()))
            results[name] = {"exit_code": process.returncode, "hard_kill": False}
        except subprocess.TimeoutExpired:
            results[name] = terminate(process)
    for stream in logs.values():
        stream.close()

    manifest.update({
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "processes": results,
        "status": "OK" if all(item["exit_code"] == 0 for item in results.values()) else "NODE_FAILED",
        "files": {name: sha256_file(run_dir / f"{name}.jsonl") for name in NODES},
    })
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"run_dir": str(run_dir), "status": manifest["status"], "processes": results}


def main() -> None:
    parser = argparse.ArgumentParser(description="Isolated multi-node RNS feasibility topology")
    parser.add_argument("--condition", choices=CONDITIONS, default="baseline")
    parser.add_argument("--mode", choices=("benign", "unknown", "announce"), default="unknown")
    parser.add_argument("--rate", type=float, default=10.0)
    parser.add_argument("--window", type=float, default=12.0)
    parser.add_argument("--start-delay", type=float, default=10.0)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--path-timeout", type=float, default=15.0)
    parser.add_argument("--connect-stagger", type=float, default=2.0,
                        help="seconds between starting the two honest measurers")
    parser.add_argument("--loglevel", type=int, default=None)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--base-port", type=int, default=44600)
    parser.add_argument("--outdir", type=Path, default=REPO_ROOT / "results" / "multinode")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be >= 1")
    if args.rate <= 0 or args.window <= 0:
        parser.error("--rate and --window must be positive")
    args.outdir.mkdir(parents=True, exist_ok=True)

    for index in range(args.repeats):
        result = run_repeat(args, index)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
