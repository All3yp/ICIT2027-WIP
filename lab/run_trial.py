#!/usr/bin/env python3
"""Bounded, isolated T0/T2 trial orchestrator for the RNS loopback laboratory.

For each repeat it creates an immutable run directory, launches a fresh server and
client (separate processes, separate RNS state), passes the server destination hash
to the client through a file, enforces timeouts, terminates both processes, and writes
a manifest with version and configuration fingerprints.

Loopback-only. No floods, no public networks, no process reuse between repeats.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parent
LINK_LAB = LAB_DIR / "link_lab.py"
DEEP_TRACE = LAB_DIR / "deep_trace.py"
RELAY = LAB_DIR / "relay.py"
SDIST = REPO_ROOT / "artifacts" / "rns-1.5.7.tar.gz"

sys.path.insert(0, str(LAB_DIR))
from link_lab import GUARDED_HARDENING, PROBE_MODES, time_to_status  # centralized definitions
from app_handlers import APP_MODES  # centralized handler vocabulary (E1)
from perturb import PERTURB_DELAY_SECONDS, PERTURB_MODES  # centralized perturbation vocabulary (E3)
from setup_loopback import SERVER, CLIENT  # centralized interface configuration


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def wait_for_event(path: Path, event: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(item.get("event") == event for item in read_events(path)):
            return True
        time.sleep(0.05)
    return False


def link_latency_seconds(client_events: list[dict]) -> float | None:
    requested = next((e for e in client_events if e.get("event") == "client_link_requested"), None)
    established = next((e for e in client_events if e.get("event") == "client_established"), None)
    if not requested or not established:
        return None
    parse = lambda value: datetime.fromisoformat(value)  # noqa: E731
    return (parse(established["timestamp_utc"]) - parse(requested["timestamp_utc"])).total_seconds()


def write_config(directory: Path, template: str, port: int) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "config"
    if target.exists():
        raise SystemExit(f"refusing to overwrite existing config: {target}")
    target.write_text(template.format(port=port), encoding="utf-8")
    return target


def terminate(process: subprocess.Popen, settle: float, hard_timeout: float = 8.0) -> dict:
    time.sleep(settle)
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=hard_timeout)
        return {"exit_code": process.returncode, "terminated_signal": "SIGINT", "hard_kill": False}
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=hard_timeout)
        return {"exit_code": process.returncode, "terminated_signal": "SIGKILL", "hard_kill": True}


def run_client_with_pause(client_cmd: list[str], client_events: Path, args: argparse.Namespace,
                          log_path: Path) -> dict:
    """Run the client, freeze it once it signals readiness, wait, then resume it.

    Freezing the process (rather than killing it) keeps the transport connection open while
    the peer sends nothing at all, so the responder's own watchdog - and not a closed socket -
    decides the link's fate. This is how E2 measures inactivity detection behaviourally.
    """
    stopped = False
    resumed = False
    resume_at = None
    with log_path.open("w", encoding="utf-8") as client_log:
        client = subprocess.Popen(client_cmd, stdout=client_log, stderr=subprocess.STDOUT,
                                  cwd=str(REPO_ROOT))
        deadline = time.monotonic() + args.client_timeout
        while client.poll() is None and time.monotonic() < deadline:
            if not stopped:
                if any(e.get("event") == "client_ready_for_pause" for e in read_events(client_events)):
                    client.send_signal(signal.SIGSTOP)
                    stopped = True
                    resume_at = time.monotonic() + args.pause_seconds
            elif time.monotonic() >= resume_at:
                client.send_signal(signal.SIGCONT)
                stopped = False
                resumed = True
                break
            time.sleep(0.1)
        if stopped:
            client.send_signal(signal.SIGCONT)
            resumed = True
        try:
            client.wait(timeout=args.client_timeout)
            exit_code = client.returncode
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait()
            exit_code = None
    return {"exit_code": exit_code, "pause_seconds": args.pause_seconds,
            "paused": resumed}


def run_repeat(args: argparse.Namespace, index: int, batch_start: float) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.outdir / f"{args.trial}_{stamp}_{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    port = args.base_port + index
    client_port = port + 100 if args.relay else port
    if not port_is_free(port) or (args.relay and not port_is_free(client_port)):
        (run_dir / "manifest.json").write_text(
            json.dumps({"trial": args.trial, "index": index, "status": "ABORTED",
                        "reason": f"port {port} or {client_port} already in use"}, indent=2) + "\n",
            encoding="utf-8")
        return {"run_dir": str(run_dir), "status": "ABORTED_PORT_IN_USE", "port": port}

    server_config = write_config(run_dir / "runtime" / "server", SERVER, port)
    client_config = write_config(run_dir / "runtime" / "client", CLIENT, client_port)
    server_events = run_dir / "server.jsonl"
    client_events = run_dir / "client.jsonl"
    destination_file = run_dir / "destination_hash"

    manifest: dict = {
        "trial": args.trial,
        "repeat_index": index,
        "run_dir": str(run_dir),
        "port": port,
        "started_utc": utc_now(),
        "probe_once": args.probe_mode == "fresh",
        "probe_mode": args.probe_mode,
        "hardening": GUARDED_HARDENING if args.harden else "off",
        "app_mode": args.app_mode,
        "observe_seconds": args.observe_seconds,
        "pause_seconds": args.pause_seconds,
        "perturb": args.perturb,
        "dup_delay": args.dup_delay,
        "extra_rtt": args.extra_rtt,
        "probe_delay": args.probe_delay,
        "data_packets": args.data_packets,
        "no_teardown": args.no_teardown,
        "trace_packets": args.trace_packets,
        "sync_inbound": args.sync_inbound,
        "relay": {
            "enabled": args.relay,
            "listen_port": client_port if args.relay else None,
            "upstream_port": port if args.relay else None,
            "duplicate_delay_seconds": args.relay_dup_delay if args.relay else None,
        },
        "fingerprints": {
            "rns_sdist_sha256": sha256_file(SDIST),
            "link_lab_sha256": sha256_file(LINK_LAB),
            "deep_trace_sha256": sha256_file(DEEP_TRACE),
            "relay_sha256": sha256_file(RELAY),
            "installed_link_py_sha256": sha256_file(
                Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages" / "RNS" / "Link.py"),
            "server_config_sha256": sha256_file(server_config),
            "client_config_sha256": sha256_file(client_config),
        },
        "interpreter": sys.executable,
        "python": sys.version.split()[0],
        "host": os.uname().nodename,
        "kernel": os.uname().release,
    }

    server_cmd = [sys.executable, str(LINK_LAB), "server",
                  "--config", str(run_dir / "runtime" / "server"),
                  "--events", str(server_events),
                  "--identity", str(run_dir / "runtime" / "server" / "identity"),
                  "--destination-out", str(destination_file),
                  "--app-mode", args.app_mode,
                  "--observe-seconds", str(args.observe_seconds),
                  "--trial-label", args.trial]
    if args.harden:
        server_cmd += ["--hardening", GUARDED_HARDENING]
    if args.sync_inbound:
        server_cmd.append("--sync-inbound")
    if args.trace_packets:
        server_cmd += ["--trace-file", str(run_dir / "server_trace.jsonl")]
    client_cmd = [sys.executable, str(LINK_LAB), "client",
                  "--config", str(run_dir / "runtime" / "client"),
                  "--events", str(client_events),
                  "--destination-file", str(destination_file),
                  "--probe-mode", args.probe_mode,
                  "--perturb", args.perturb,
                  "--perturb-delay", str(args.perturb_delay),
                  "--dup-delay", str(args.dup_delay),
                  "--probe-delay", str(args.probe_delay),
                  "--data-packets", str(args.data_packets),
                  "--hold-seconds", str(args.hold_seconds),
                  "--trial-label", args.trial]
    if args.extra_rtt is not None:
        client_cmd += ["--extra-rtt", str(args.extra_rtt)]
    if args.no_teardown:
        client_cmd.append("--no-teardown")
    if args.trace_packets:
        client_cmd += ["--trace-file", str(run_dir / "client_trace.jsonl")]

    t_server_start = time.monotonic()
    with (run_dir / "server.stdout.log").open("w", encoding="utf-8") as server_log:
        server = subprocess.Popen(server_cmd, stdout=server_log, stderr=subprocess.STDOUT,
                                  cwd=str(REPO_ROOT))

    ready = False
    deadline = time.monotonic() + args.server_ready_timeout
    while time.monotonic() < deadline:
        if destination_file.exists() and destination_file.read_text(encoding="utf-8").strip():
            ready = True
            break
        if server.poll() is not None:
            break
        time.sleep(0.2)
    manifest["server_ready"] = ready
    manifest["server_ready_seconds"] = round(time.monotonic() - t_server_start, 3)

    client_result: dict = {"exit_code": None}
    termination: dict = {"exit_code": None}
    status = "SERVER_NOT_READY"
    relay_process = None
    if ready and args.relay:
        relay_events = run_dir / "relay.jsonl"
        relay_cmd = [sys.executable, str(RELAY),
                     "--listen", str(client_port), "--upstream", str(port),
                     "--dup-delay", str(args.relay_dup_delay),
                     "--events", str(relay_events)]
        relay_log = (run_dir / "relay.stdout.log").open("w", encoding="utf-8")
        relay_process = subprocess.Popen(relay_cmd, stdout=relay_log, stderr=subprocess.STDOUT,
                                         cwd=str(REPO_ROOT))
        relay_ready = wait_for_event(relay_events, "relay_listening", timeout=10.0)
        manifest["relay_ready"] = relay_ready
        if not relay_ready:
            status = "RELAY_NOT_READY"
            ready = False
    if ready:
        t_client_start = time.monotonic()
        if args.pause_seconds > 0:
            client_result = run_client_with_pause(client_cmd, client_events, args,
                                                  run_dir / "client.stdout.log")
            client_result["duration_seconds"] = round(time.monotonic() - t_client_start, 3)
        else:
            with (run_dir / "client.stdout.log").open("w", encoding="utf-8") as client_log:
                completed = subprocess.run(client_cmd, stdout=client_log, stderr=subprocess.STDOUT,
                                           cwd=str(REPO_ROOT), timeout=args.client_timeout)
            client_result = {"exit_code": completed.returncode,
                             "duration_seconds": round(time.monotonic() - t_client_start, 3)}
        termination = terminate(server, args.server_settle)
        status = "OK" if client_result.get("exit_code") == 0 else "CLIENT_FAILED"
    else:
        termination = terminate(server, 0.0)
    if relay_process is not None:
        terminate(relay_process, 0.2)

    server_ev = read_events(server_events)
    client_ev = read_events(client_events)
    server_callbacks = [e for e in server_ev if e.get("event") == "server_established"]
    client_established = [e for e in client_ev if e.get("event") == "client_established"]
    observations = [e for e in client_ev if e.get("event") == "client_finished_observation"]
    ctrl = observations[-1] if observations else {}
    app_keys = ("app_callbacks", "app_sessions_created", "app_accounting_units",
                "app_redundant_calls", "app_invariant_violations", "app_sessions_for_link")
    app_fields = {key: (server_callbacks[-1].get(key) if server_callbacks else None) for key in app_keys}
    status_events = [e for e in server_ev if e.get("event") == "server_status"]
    perturbation = next((e for e in client_ev if e.get("event") == "perturbation_events"), {})

    manifest.update({
        "finished_utc": utc_now(),
        "status": status,
        "client": client_result,
        "server_termination": termination,
        "wall_seconds": round(time.monotonic() - batch_start, 3),
        "link_latency_seconds": link_latency_seconds(client_ev),
        "server_run_ids": sorted({e.get("run_id") for e in server_ev}),
        "client_run_ids": sorted({e.get("run_id") for e in client_ev}),
        "client_status_final": ctrl.get("status"),
        "client_callback_count": ctrl.get("client_callback_count"),
        "client_active_confirmed": any(e.get("status") == 2 for e in client_established),
        "client_data_sent": sum(1 for e in client_ev if e.get("event") == "client_data_sent"),
        "server_established_count": len(server_callbacks),
        "server_callback_statuses": [e.get("status_name") for e in server_callbacks],
        "server_status_transitions": [
            {key: e.get(key) for key in ("status_name", "elapsed_seconds", "no_inbound_for",
                                         "keepalive", "stale_time")} for e in status_events],
        "time_to_stale_seconds": time_to_status(server_ev, "STALE"),
        "time_to_closed_seconds": time_to_status(server_ev, "CLOSED"),
        "server_teardown_names": sorted({e.get("teardown_name") for e in server_ev
                                         if e.get("event") == "server_link_closed"
                                         and e.get("teardown_name")}),
        "server_link_data_statuses": [e.get("status_name") for e in server_ev
                                      if e.get("event") == "server_link_data"],
        "server_link_data_early": [
            {key: e.get(key) for key in ("status_name", "bytes", "handler_registered_at")}
            for e in server_ev if e.get("event") == "server_link_data_early"],
        "server_destination_link_series": [
            [entry.get("status_name") for entry in e.get("links", [])]
            for e in server_ev if e.get("event") == "destination_link_snapshot"],
        "perturbation_events": perturbation.get("events"),
        "perturbation_consumed": perturbation.get("consumed"),
        "trace_files": {name: sha256_file(run_dir / name)
                        for name in ("server_trace.jsonl", "client_trace.jsonl", "relay.jsonl")},
        "relay_events": read_events(run_dir / "relay.jsonl"),
        **app_fields,
        "server_callbacks_by_link": (
            {lid: sum(1 for e in server_callbacks if e.get("link_id") == lid)
             for lid in {e.get("link_id") for e in server_callbacks}}),
        "server_link_ids": sorted({e.get("link_id") for e in server_callbacks}),
        "client_link_ids": sorted({e.get("link_id") for e in client_established}),
        "correlated_link_ids": sorted(
            {e.get("link_id") for e in server_callbacks}
            & {e.get("link_id") for e in client_established}),
        "probe_sent": any(e.get("event") == "fresh_lrrtt_probe_sent" for e in client_ev),
        "replay_injected": any(e.get("event") == "replayed_lrrtt_sent" for e in client_ev),
        "hardening_installed": any(e.get("event") == "hardening_installed" for e in server_ev),
        "hardening_rtt_rejected": sum(1 for e in server_ev if e.get("event") == "hardening_rtt_rejected"),
        "server_link_closed_events": sum(1 for e in server_ev if e.get("event") == "server_link_closed"),
        "client_link_closed_events": sum(1 for e in client_ev if e.get("event") == "client_link_closed"),
        "server_callback_states": [
            {key: e.get(key) for key in ("callback_number", "status", "rtt", "expected_hops",
                                         "keepalive", "stale_time", "age_seconds")}
            for e in server_callbacks],
        "server_late_samples": [
            {key: e.get(key) for key in ("status", "rx", "rxbytes", "rtt", "keepalive", "age_seconds")}
            for e in server_ev if e.get("event") == "server_link_late_sample"],
        "run_failed_events": [e.get("reason") for e in client_ev if e.get("event") == "run_failed"],
    })
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded loopback RNS trial orchestrator")
    parser.add_argument("--trial", default="T0", help="trial label, e.g. T0 / T2 / T2ctl")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--base-port", type=int, default=42500)
    parser.add_argument("--outdir", type=Path, default=REPO_ROOT / "results" / "trials")
    parser.add_argument("--probe-once", action="store_true", help="T2: send exactly one LRRTT after ACTIVE")
    parser.add_argument("--probe-mode", choices=PROBE_MODES, help="client probe mode; defaults to fresh with --probe-once, else none")
    parser.add_argument("--extra-rtt", type=float, help="client: RTT value supplied by probe mode 'fixed' (E2)")
    parser.add_argument("--probe-delay", type=float, default=1.0,
                        help="client: seconds after establishment before probing (E2)")
    parser.add_argument("--harden", action="store_true", help="install the runtime responder-rtt pre-state guard on the server")
    parser.add_argument("--app-mode", choices=APP_MODES, default="counting",
                        help="server: establishment-callback handler shape (E1)")
    parser.add_argument("--observe-seconds", type=float, default=0.0,
                        help="server: behavioural link-state observation window (E2)")
    parser.add_argument("--pause-seconds", type=float, default=0.0,
                        help="orchestrator: freeze the client for this long after it signals readiness (E2)")
    parser.add_argument("--perturb", choices=PERTURB_MODES, default="none",
                        help="client: one-shot perturbation of the establishment LRRTT (E3)")
    parser.add_argument("--perturb-delay", type=float, default=PERTURB_DELAY_SECONDS,
                        help="client: how long mode 'delay' withholds the establishment LRRTT")
    parser.add_argument("--dup-delay", type=float, default=0.0,
                        help="client: time between the two identical copies in mode 'dup'")
    parser.add_argument("--data-packets", type=int, default=0,
                        help="client: benign DATA packets sent right after establishment")
    parser.add_argument("--hold-seconds", type=float, default=0.0,
                        help="client: stay alive and silent for this long before finishing")
    parser.add_argument("--no-teardown", action="store_true",
                        help="client: exit without tearing the link down")
    parser.add_argument("--trace-packets", action="store_true",
                        help="record the observer-only inbound/outbound ordering trace for both roles")
    parser.add_argument("--sync-inbound", action="store_true",
                        help="server: mechanism control, process inbound packets inline (USE_INBOUND_QUEUE=no)")
    parser.add_argument("--relay", action="store_true",
                        help="insert the key-less on-path relay (adversary M2) between client and server")
    parser.add_argument("--relay-dup-delay", type=float, default=0.0,
                        help="relay: seconds between the two emissions of the captured LRRTT frame")
    parser.add_argument("--server-ready-timeout", type=float, default=20.0)
    parser.add_argument("--client-timeout", type=float, default=90.0)
    parser.add_argument("--server-settle", type=float, default=3.0,
                        help="seconds to let the server log callbacks after the client exits")
    args = parser.parse_args()
    if args.probe_mode is None:
        args.probe_mode = "fresh" if args.probe_once else "none"
    if args.probe_once and args.probe_mode != "fresh":
        parser.error("--probe-once cannot be combined with --probe-mode {mode}".format(mode=args.probe_mode))
    if args.probe_mode == "fixed" and args.extra_rtt is None:
        parser.error("--probe-mode fixed requires --extra-rtt")
    if args.pause_seconds < 0 or args.observe_seconds < 0 or args.hold_seconds < 0 or args.data_packets < 0:
        parser.error("--pause-seconds, --observe-seconds, --hold-seconds and --data-packets must not be negative")
    if args.probe_delay < 0:
        parser.error("--probe-delay must not be negative")
    if args.dup_delay < 0:
        parser.error("--dup-delay must not be negative")
    if args.relay_dup_delay < 0:
        parser.error("--relay-dup-delay must not be negative")
    if args.relay and args.perturb != "none":
        parser.error("--relay and --perturb are alternative duplication mechanisms")
    if args.repeats < 1:
        parser.error("--repeats must be >= 1")
    args.outdir.mkdir(parents=True, exist_ok=True)

    batch_start = time.monotonic()
    results = []
    for index in range(args.repeats):
        result = run_repeat(args, index, batch_start)
        results.append(result)
        print(json.dumps({k: result.get(k) for k in (
            "run_dir", "status", "probe_mode", "hardening", "app_mode", "perturb",
            "client_status_final", "server_established_count", "server_callbacks_by_link",
            "correlated_link_ids", "probe_sent", "replay_injected", "hardening_rtt_rejected",
            "server_link_closed_events", "client_link_closed_events",
            "app_sessions_created", "app_redundant_calls", "app_invariant_violations",
            "time_to_stale_seconds", "time_to_closed_seconds")}, indent=2))

    summary = {
        "trial": args.trial,
        "repeats": args.repeats,
        "probe_once": args.probe_mode == "fresh",
        "probe_mode": args.probe_mode,
        "hardening": GUARDED_HARDENING if args.harden else "off",
        "app_mode": args.app_mode,
        "perturb": args.perturb,
        "completed_utc": utc_now(),
        "statuses": sorted({r.get("status") for r in results}),
        "results": results,
    }
    (args.outdir / f"batch_{args.trial}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
     ).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
