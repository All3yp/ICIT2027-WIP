#!/usr/bin/env python3
"""One node of the isolated multi-node RNS topology used for the cross-peer feasibility test.

Roles
  hub        transport instance (enable_transport = yes), one TCP server interface
  announcer  honest node H1: owns one SINGLE destination and announces it periodically
  measurer   honest node H2/H3: repeatedly discovers the announcer and establishes a link,
             recording success, latency and per-process counters
  adversary  participant A: emits protocol-compliant control traffic at a bounded rate, either
             path requests for a real destination, path requests for random destinations, or
             announces for synthetic destinations

Loopback only. Every node is a separate process with its own configuration and storage.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import resource
import signal
import sys
import threading
import time

APP_NAME = "reticulum_research"
ASPECT = "multinode"
ANNOUNCE_INTERVAL = 2.0
ATTEMPT_INTERVAL = 1.0
PATH_REQUEST_INTERVAL = 5.0
LINK_TIMEOUT = 5.0
COUNTER_INTERVAL = 1.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventWriter:
    def __init__(self, path: Path, role: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.role = role
        self.lock = threading.Lock()

    def log(self, event: str, **fields: object) -> None:
        item = {"timestamp_utc": utc_now(), "role": self.role, "event": event, **fields}
        with self.lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(item, default=str) + "\n")


def counters(RNS: object) -> dict:
    return {
        "rx_packets": RNS.Transport.rx_packets,
        "path_table_size": len(RNS.Transport.path_table),
        "queue_depth": RNS.Transport.inbound_queues.qsize() if RNS.Transport.inbound_queues else None,
        "cpu_seconds": round(sum(resource.getrusage(resource.RUSAGE_SELF)[:2]), 3),
        "rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def announcer(RNS: object, args: argparse.Namespace, log: EventWriter) -> None:
    identity = RNS.Identity()
    destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                                  APP_NAME, ASPECT)
    Path(args.target_out).write_text(destination.hexhash + "\n", encoding="utf-8")
    log.log("announcer_ready", destination_hash=destination.hexhash)

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        destination.announce()
        log.log("announce_sent", destination_hash=destination.hexhash, **counters(RNS))
        time.sleep(ANNOUNCE_INTERVAL)
    log.log("announcer_finished", **counters(RNS))


def measurer(RNS: object, args: argparse.Namespace, log: EventWriter) -> None:
    target = bytes.fromhex(Path(args.target_file).read_text(encoding="utf-8").strip())
    log.log("measurer_started", target=target.hex())

    acquired_at = None
    wait_start = time.monotonic()
    last_request = 0.0
    while not RNS.Transport.has_path(target) and time.monotonic() - wait_start < args.path_timeout:
        # Request at most once every PATH_REQUEST_INTERVAL: RNS batches repeat requests for a
        # destination that is already being resolved, so a request storm only delays discovery.
        if time.monotonic() - last_request >= PATH_REQUEST_INTERVAL:
            RNS.Transport.request_path(target)
            last_request = time.monotonic()
        time.sleep(0.25)
    if RNS.Transport.has_path(target):
        acquired_at = round(time.monotonic() - wait_start, 3)
        log.log("path_acquired", target=target.hex(), seconds=acquired_at, **counters(RNS))
    else:
        log.log("path_unavailable", target=target.hex(), **counters(RNS))

    identity = RNS.Identity.recall(target)
    destination = None
    if identity is not None:
        destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                      APP_NAME, ASPECT)

    # The measurement window starts at process start, not after route discovery, so every
    # honest node covers the same relative interval as the adversary.
    deadline = args.started_monotonic + args.duration
    last_request = time.monotonic()
    while time.monotonic() < deadline:
        if destination is None:
            identity = RNS.Identity.recall(target)
            if identity is not None:
                destination = RNS.Destination(identity, RNS.Destination.OUT,
                                              RNS.Destination.SINGLE, APP_NAME, ASPECT)
        if not RNS.Transport.has_path(target):
            if time.monotonic() - last_request >= PATH_REQUEST_INTERVAL:
                RNS.Transport.request_path(target)
                last_request = time.monotonic()
            log.log("path_lost", target=target.hex(), **counters(RNS))
            time.sleep(ATTEMPT_INTERVAL)
            continue

        established = threading.Event()
        started = time.monotonic()
        link = RNS.Link(destination, established_callback=lambda _link: established.set())
        ok = established.wait(LINK_TIMEOUT)
        latency = round(time.monotonic() - started, 4)
        log.log("link_attempt", success=ok, latency_seconds=latency,
                path_known=True, **counters(RNS))
        if ok:
            link.teardown()
        else:
            link.teardown()
        time.sleep(ATTEMPT_INTERVAL)
    log.log("measurer_finished", **counters(RNS))


def adversary(RNS: object, args: argparse.Namespace, log: EventWriter) -> None:
    time.sleep(args.start_delay)
    started = utc_now()
    started_mono = time.monotonic()
    log.log("adversary_started", mode=args.mode, rate=args.rate, window_seconds=args.window,
            window_started_utc=started, **counters(RNS))

    real_target = None
    if args.mode == "benign":
        real_target = bytes.fromhex(Path(args.target_file).read_text(encoding="utf-8").strip())
    identity = RNS.Identity()
    sent = 0
    interval = 1.0 / args.rate if args.rate > 0 else 1.0
    deadline = started_mono + args.window
    while time.monotonic() < deadline:
        if args.mode == "benign":
            RNS.Transport.request_path(real_target)
        elif args.mode == "unknown":
            RNS.Transport.request_path(RNS.Identity.get_random_hash()[:16])
        elif args.mode == "announce":
            destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                                          APP_NAME, f"{ASPECT}-synthetic-{sent}")
            destination.announce()
        else:
            raise SystemExit(f"unknown adversary mode {args.mode}")
        sent += 1
        time.sleep(interval)

    log.log("adversary_finished", mode=args.mode, sent=sent, elapsed_seconds=round(
        time.monotonic() - started_mono, 3), window_started_utc=started,
        window_finished_utc=utc_now(), **counters(RNS))


def hub(RNS: object, args: argparse.Namespace, log: EventWriter) -> None:
    log.log("hub_ready", interfaces=len(RNS.Transport.interfaces), **counters(RNS))
    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        log.log("hub_counters", interfaces=len(RNS.Transport.interfaces), **counters(RNS))
        time.sleep(COUNTER_INTERVAL)
    log.log("hub_finished", **counters(RNS))


def main() -> None:
    parser = argparse.ArgumentParser(description="Isolated multi-node RNS topology node")
    parser.add_argument("role", choices=("hub", "announcer", "measurer", "adversary"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--target-out")
    parser.add_argument("--target-file")
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--path-timeout", type=float, default=20.0)
    parser.add_argument("--mode", choices=("benign", "unknown", "announce"), default="benign")
    parser.add_argument("--rate", type=float, default=10.0)
    parser.add_argument("--window", type=float, default=12.0)
    parser.add_argument("--start-delay", type=float, default=10.0)
    parser.add_argument("--loglevel", type=int, default=None,
                        help="RNS log level for diagnostics (writes a large stdout log)")
    args = parser.parse_args()

    if not (args.config / "config").exists():
        parser.error("config directory must contain a file named 'config'")
    conf = (args.config / "config").read_text(encoding="utf-8")
    if "127.0.0.1" not in conf or "share_instance = no" not in conf or "AutoInterface" in conf:
        parser.error("refusing non-loopback or shared-instance configuration")

    import RNS  # noqa: PLC0415

    if args.loglevel is not None:
        RNS.loglevel = args.loglevel

    log = EventWriter(args.events, args.role)
    log.log("process_started", config=str(args.config))
    args.started_monotonic = time.monotonic()
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    RNS.Reticulum(str(args.config))

    try:
        if args.role == "hub":
            hub(RNS, args, log)
        elif args.role == "announcer":
            announcer(RNS, args, log)
        elif args.role == "measurer":
            measurer(RNS, args, log)
        else:
            adversary(RNS, args, log)
    except SystemExit:
        raise
    except Exception as exc:  # keep failures visible in the artifact
        log.log("run_failed", reason=repr(exc))
        raise


if __name__ == "__main__":
    main()
