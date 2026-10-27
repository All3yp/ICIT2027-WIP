#!/usr/bin/env python3
"""Bounded loopback-only RNS link-establishment harness (T0/T2 and controls).

Authorized isolated laboratory use only: no denial-of-service loops, no public
network use. Client and server run as separate, non-shared RNS instances that
reach each other exclusively over loopback TCP.

Client probe modes (exactly one additional LRRTT after ACTIVE, or none):
  none      - no probe (T0 baseline / matched control)
  fresh     - one newly encrypted LRRTT (T2)
  fixed     - one newly encrypted LRRTT supplying --extra-rtt seconds (E2 timer control)
  inflated  - one newly encrypted LRRTT supplying an oversized RTT value
  replay    - one fresh LRRTT, then the identical wire bytes re-transmitted (D2)
  corrupt   - one LRRTT whose token HMAC is broken (D3 authenticity control)
  malformed - one validly encrypted LRRTT with a non-msgpack payload

Server hardening candidate (runtime patch, installed RNS package untouched):
  guarded-rtt - enforce the establishment pre-state on the responder RTT path,
                mirroring the guard the initiator path already applies.

Application handler shapes for the establishment callback (E1): counting, nonidempotent,
idempotent (see lab/app_handlers.py). Packet perturbation modes for E3: dup, drop, delay,
reorder, retransmit (see lab/perturb.py).
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app_handlers import APP_MODES, build_handler  # noqa: E402
from deep_trace import install as install_packet_trace  # noqa: E402
from perturb import PERTURB_DELAY_SECONDS, PERTURB_MODES, PacketPerturber  # noqa: E402

APP_NAME = "reticulum_research"
ASPECT = "link_pilot"
HASH_HEX_LENGTH = 32
ANNOUNCE_INTERVAL = 5.0
INTERFACE_POLL_INTERVAL = 0.25
PATH_REQUEST_INTERVAL = 0.5
HEARTBEAT_INTERVAL = 5.0
PROBE_MODES = ("none", "fresh", "fixed", "inflated", "replay", "corrupt", "malformed")
HARDENING_MODES = ("off", "guarded-rtt")
GUARDED_HARDENING = "guarded-rtt"
PROBE_SETTLE_SECONDS = 1.0
REPLAY_DELAY_SECONDS = 0.5
OBSERVATION_SECONDS = 2.0
MALFORMED_PLAINTEXT = b"\xc1"  # never-used msgpack byte: decrypts, then unpacking fails
INFLATED_RTT_SECONDS = 1.0e6  # supplied RTT far above any real measurement, for the bound check
LATE_SAMPLE_SECONDS = 2.0     # delay for the post-probe responder link sample
STATUS_SAMPLE_INTERVAL = 0.25  # responder link-state sampling period
STATUS_NAMES = {0: "PENDING", 1: "HANDSHAKE", 2: "ACTIVE", 3: "STALE", 4: "CLOSED"}
TEARDOWN_NAMES = {0x01: "TIMEOUT", 0x02: "INITIATOR_CLOSED", 0x03: "DESTINATION_CLOSED"}
DATA_PAYLOAD = "e3-data-{index}"  # benign payload for the ordering/perturbation trials


class EventWriter:
    def __init__(self, destination: Path, role: str, trial: str):
        self.destination = destination
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.role = role
        self.trial = trial
        self.run_id = str(uuid.uuid4())

    def log(self, event: str, **fields: object) -> None:
        item = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "role": self.role,
            "trial": self.trial,
            "event": event,
            **fields,
        }
        with self.lock:
            with self.destination.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(item, default=str) + "\n")
        print(json.dumps(item, default=str), flush=True)


def linkid(link: object) -> str:
    value = getattr(link, "link_id", None)
    return value.hex() if isinstance(value, bytes) else str(value)


def corrupt_token(token: bytes) -> bytes:
    """Flip one bit of the trailing token HMAC, leaving the ciphertext intact.

    The receiver's link-key check is an HMAC over the whole token, so this makes the
    token fail authenticity while remaining a well-formed packet on the wire.
    """
    if len(token) < 2:
        raise ValueError("token too short to corrupt")
    return token[:-1] + bytes([token[-1] ^ 0x01])


def status_name(value: object) -> str:
    return STATUS_NAMES.get(value, str(value))


def link_state(link: object) -> dict:
    """Responder-visible link state, for consequence analysis (values only)."""
    activated_at = getattr(link, "activated_at", None)
    return {
        "status": getattr(link, "status", None),
        "status_name": status_name(getattr(link, "status", None)),
        "rtt": None if getattr(link, "rtt", None) is None else round(link.rtt, 6),
        "expected_hops": getattr(link, "expected_hops", None),
        "establishment_rate": None if getattr(link, "establishment_rate", None) is None
                              else round(link.establishment_rate, 6),
        "keepalive": None if getattr(link, "keepalive", None) is None else round(link.keepalive, 3),
        "stale_time": None if getattr(link, "stale_time", None) is None else round(link.stale_time, 3),
        "activated_at": None if activated_at is None else round(activated_at, 6),
        "age_seconds": None if activated_at is None else round(link.get_age(), 6),
    }


def time_to_status(events: list[dict], status: str) -> float | None:
    """Seconds from the first establishment callback to the first sample in `status`."""
    established = next((e for e in events if e.get("event") == "server_established" and e.get("callback_number") == 1), None)
    reached = next((e for e in events if e.get("event") == "server_status" and e.get("status_name") == status), None)
    if not established or not reached:
        return None
    parse = datetime.fromisoformat
    return round((parse(reached["timestamp_utc"]) - parse(established["timestamp_utc"])).total_seconds(), 3)


def install_responder_guard(RNS: object, log: EventWriter) -> None:
    """Install the H-A hardening candidate: require HANDSHAKE pre-state on the RTT path.

    This mirrors the guard the initiator path already enforces in Link.validate_proof()
    ("Invalid link state for proof validation") and is applied as a runtime patch, so the
    installed RNS package on disk is never modified.
    """
    original = RNS.Link.rtt_packet

    def guarded_rtt_packet(self: object, packet: object) -> object:
        if self.status != RNS.Link.HANDSHAKE:
            log.log(
                "hardening_rtt_rejected",
                link_id=linkid(self),
                status=self.status,
                note="LRRTT ignored: link is not in HANDSHAKE (pre-state guard)",
            )
            return None
        return original(self, packet)

    RNS.Link.rtt_packet = guarded_rtt_packet
    log.log(
        "hardening_installed",
        hardening=GUARDED_HARDENING,
        guard="responder rtt_packet requires Link.HANDSHAKE pre-state",
        patch_target="RNS.Link.rtt_packet",
    )


def install_perturber(RNS: object, perturber: PacketPerturber) -> None:
    """Route this process's outbound transmissions through the one-shot perturber (E3).

    `Packet.send` is wrapped only to tag the next transmission with the sending packet's
    context, so the perturber can recognise the establishment `LRRTT`. Both hooks are
    process-local runtime patches; the installed RNS package on disk is untouched.
    """
    original_transmit = RNS.Transport.__dict__["transmit"]
    original_send = RNS.Packet.send

    def annotated_send(packet_self: object) -> object:
        perturber.annotate(getattr(packet_self, "context", None), getattr(packet_self, "packet_type", None))
        return original_send(packet_self)

    def transmitting(interface: object, raw: bytes) -> object:
        context, _packet_type = perturber.pending_context or (None, None)
        is_lrrtt = context == RNS.Packet.LRRTT
        if perturber.handle_outbound(is_lrrtt, interface, raw, original_transmit):
            perturber.handle_followup(is_lrrtt, original_transmit)
            return None
        result = original_transmit(interface, raw)
        perturber.handle_followup(is_lrrtt, original_transmit)
        return result

    RNS.Packet.send = annotated_send
    RNS.Transport.transmit = staticmethod(transmitting)


def send_capture(RNS: object, packet: object) -> tuple[object, list[tuple[object, bytes]]]:
    """Send one packet while capturing (interface, raw bytes) handed to the wire."""
    original = RNS.Transport.__dict__["transmit"]
    captured: list[tuple[object, bytes]] = []

    def capturing_transmit(interface: object, raw: bytes) -> object:
        captured.append((interface, bytes(raw)))
        return original(interface, raw)

    RNS.Transport.transmit = staticmethod(capturing_transmit)
    try:
        accepted = packet.send()
    finally:
        RNS.Transport.transmit = staticmethod(original)
    return accepted, captured


def destination_hash(value: str) -> bytes:
    candidate = str(value).strip()
    if len(candidate) != HASH_HEX_LENGTH:
        raise ValueError(
            "destination hash must be exactly {expected} hexadecimal characters, got {actual} ({value!r})".format(
                expected=HASH_HEX_LENGTH, actual=len(candidate), value=candidate
            )
        )
    try:
        return bytes.fromhex(candidate)
    except ValueError as exc:
        raise ValueError("destination hash is not valid hexadecimal: {value!r}".format(value=candidate)) from exc


def interface_snapshot(RNS: object) -> list[dict]:
    snapshot = []
    for interface in list(RNS.Transport.interfaces):
        snapshot.append(
            {
                "interface": str(interface),
                "name": getattr(interface, "name", None),
                "online": bool(getattr(interface, "online", False)),
                "in": bool(getattr(interface, "IN", False)),
                "out": bool(getattr(interface, "OUT", False)),
                "mode": getattr(interface, "mode", None),
                "never_connected": getattr(interface, "never_connected", None),
            }
        )
    return snapshot


def usable_interface_present(RNS: object) -> bool:
    for interface in list(RNS.Transport.interfaces):
        if getattr(interface, "online", False) and getattr(interface, "OUT", False):
            return True
    return False


def await_usable_interface(RNS: object, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if usable_interface_present(RNS):
            return True
        time.sleep(INTERFACE_POLL_INTERVAL)
    return usable_interface_present(RNS)


def known_path_hashes(RNS: object) -> list[str]:
    return [path_hash.hex() for path_hash in list(RNS.Transport.path_table.keys())]


def load_identity(RNS: object, args: argparse.Namespace, log: EventWriter) -> object:
    if not args.identity:
        log.log(
            "identity_ephemeral",
            note="no --identity given, the destination hash changes on every server start",
        )
        return RNS.Identity()
    path = Path(args.identity)
    if path.exists():
        identity = RNS.Identity.from_file(str(path))
        if identity is None:
            raise RuntimeError("could not load a valid identity from {path}".format(path=path))
        log.log("identity_loaded", path=str(path))
        return identity
    identity = RNS.Identity()
    path.parent.mkdir(parents=True, exist_ok=True)
    identity.to_file(str(path))
    log.log("identity_created", path=str(path))
    return identity


def instrument_link_callbacks(RNS: object, log: EventWriter) -> None:
    """Attach observers at link construction, in the responder process only.

    An application can only obtain the link object inside `link_established`, so any link packet
    that arrives before establishment is delivered by the library but has no application handler
    to receive it. This runtime patch registers an early handler purely as an observer, making
    that delivery visible; it does not change link behaviour.
    """
    original_init = RNS.Link.__init__

    def patched_init(self: object, *args: object, **kwargs: object) -> None:
        original_init(self, *args, **kwargs)
        self.set_packet_callback(lambda data, packet: log.log(
            "server_link_data_early", link_id=linkid(self), status=self.status,
            status_name=status_name(self.status), bytes=len(data),
            handler_registered_at="link_construction"))
        self.set_link_closed_callback(lambda link: log.log(
            "server_link_closed_early", link_id=linkid(link), status=link.status,
            status_name=status_name(link.status),
            teardown_name=TEARDOWN_NAMES.get(getattr(link, "teardown_reason", None))))

    RNS.Link.__init__ = patched_init
    log.log("link_callbacks_instrumented", patch_target="RNS.Link.__init__")


def server(RNS: object, args: argparse.Namespace, log: EventWriter) -> None:
    if args.sync_inbound:
        # Mechanism control: process inbound packets on the receiving thread instead of the
        # single queued worker, so the duplicate filter's check and its state update are no
        # longer separated by a queue boundary. Set before construction so no worker starts.
        RNS.Transport.USE_INBOUND_QUEUE = False
    RNS.Reticulum(str(args.config))
    if args.trace_file:
        install_packet_trace(RNS, Path(args.trace_file), "server")
        log.log("packet_trace_installed", path=str(args.trace_file), sync_inbound=args.sync_inbound)
    if args.hardening != "off":
        install_responder_guard(RNS, log)
    instrument_link_callbacks(RNS, log)
    identity = load_identity(RNS, args, log)
    destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT)
    counts: dict[str, int] = {}
    app_state, app_handler = build_handler(args.app_mode)
    log.log("app_handler_ready", app_mode=args.app_mode)

    def closed(link: object) -> None:
        log.log("server_link_closed", link_id=linkid(link),
                teardown_reason=getattr(link, "teardown_reason", None),
                teardown_name=TEARDOWN_NAMES.get(getattr(link, "teardown_reason", None)),
                **link_state(link))

    def late_sample(link: object) -> None:
        log.log("server_link_late_sample", link_id=linkid(link), rx=link.rx, rxbytes=link.rxbytes,
                **link_state(link))

    def link_data(data: bytes, packet: object) -> None:
        log.log("server_link_data", link_id=linkid(getattr(packet, "link", None)) if getattr(packet, "link", None) else None,
                status=getattr(packet, "link", None) and packet.link.status,
                status_name=getattr(packet, "link", None) and status_name(packet.link.status),
                bytes=len(data))

    def monitor(link: object, seconds: float) -> None:
        """Sample the responder's own link state until it closes or the window ends (E2).

        This records observed state transitions - the behavioural outcome - rather than the
        internal RTT/keepalive values that drive them.
        """
        start = time.time()
        last = None
        while True:
            current = link.status
            if current != last:
                log.log("server_status", link_id=linkid(link), status=current,
                        status_name=status_name(current),
                        elapsed_seconds=round(time.time() - start, 3),
                        no_inbound_for=round(link.no_inbound_for(), 3),
                        keepalive=getattr(link, "keepalive", None),
                        stale_time=getattr(link, "stale_time", None))
                last = current
            if current == RNS.Link.CLOSED or (time.time() - start) >= seconds:
                break
            time.sleep(STATUS_SAMPLE_INTERVAL)

    def accepted(link: object) -> None:
        link.set_link_closed_callback(closed)
        link.set_packet_callback(link_data)
        lid = linkid(link)
        counts[lid] = counts.get(lid, 0) + 1
        log.log("server_established", link_id=lid, callback_number=counts[lid], **link_state(link),
                **app_handler(lid))
        # One delayed sample of the responder's own link counters, so the number of inbound
        # link packets actually processed can be compared across conditions.
        sampler = threading.Timer(LATE_SAMPLE_SECONDS, late_sample, args=(link,))
        sampler.daemon = True
        sampler.start()
        # Behavioural observation window, started once per link (not once per callback).
        if args.observe_seconds > 0 and counts[lid] == 1:
            log.log("server_observation_started", link_id=lid, window_seconds=args.observe_seconds)
            watcher = threading.Thread(target=monitor, args=(link, args.observe_seconds), daemon=True)
            watcher.start()

    def watch_destination_links() -> None:
        """Sample every link this responder holds, independent of any callback.

        Needed for conditions in which establishment never completes (e.g. a dropped
        establishment packet), where no `link_established` callback fires but the responder
        still holds a link in `HANDSHAKE`. Logs on change and at least every 5 seconds.
        """
        last_snapshot = None
        last_log = 0.0
        while True:
            try:
                held = list(destination.links)
                snapshot = tuple((linkid(link), link.status) for link in held)
                now = time.time()
                if snapshot != last_snapshot or (held and now - last_log >= ANNOUNCE_INTERVAL):
                    log.log("destination_link_snapshot", links=[
                        {"link_id": linkid(link), "status": link.status,
                         "status_name": status_name(link.status),
                         "keepalive": getattr(link, "keepalive", None),
                         "stale_time": getattr(link, "stale_time", None),
                         "no_inbound_for": round(link.no_inbound_for(), 3)} for link in held])
                    last_snapshot = snapshot
                    last_log = now
            except Exception as exc:  # never let the observer disturb the experiment
                log.log("destination_link_watch_error", reason=repr(exc))
                return
            time.sleep(STATUS_SAMPLE_INTERVAL)

    watcher_thread = threading.Thread(target=watch_destination_links, daemon=True)
    watcher_thread.start()
    log.log("destination_link_watch_started", interval_seconds=STATUS_SAMPLE_INTERVAL)

    destination.set_link_established_callback(accepted)
    log.log("interfaces_initialised", interfaces=interface_snapshot(RNS))
    log.log("destination_ready", destination_hash=destination.hexhash)
    if args.destination_out:
        target = Path(args.destination_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(destination.hexhash + "\n", encoding="utf-8")
        log.log("destination_hash_written", path=str(target), destination_hash=destination.hexhash)
    interface_count = len(RNS.Transport.interfaces)
    try:
        # Periodic benign announces help the new client discover this local destination.
        while True:
            current_count = len(RNS.Transport.interfaces)
            if current_count != interface_count:
                log.log(
                    "interfaces_changed",
                    previous=interface_count,
                    current=current_count,
                    interfaces=interface_snapshot(RNS),
                )
                interface_count = current_count
            # Callback-independent view of every link this responder holds is produced by the
            # `watch_destination_links` thread (see above), which also covers links that never
            # reach the establishment callback.
            destination.announce()
            log.log("destination_announced")
            time.sleep(ANNOUNCE_INTERVAL)
    except KeyboardInterrupt:
        log.log("server_stopped", callbacks_by_link=counts)


def send_probe(RNS: object, umsgpack: object, link: object, mode: str, log: EventWriter,
               extra_rtt: float | None = None) -> None:
    """Send the single additional LRRTT for the selected probe mode.

    All modes transmit at most one additional link-scoped packet; 'replay' re-transmits the
    identical captured wire bytes of the fresh packet instead of a newly encrypted one.
    'fixed' and 'inflated' supply a sender-chosen RTT value, to probe the responder's adoption
    of sender-supplied timing state.
    """
    lid = linkid(link)
    if mode == "malformed":
        supplied_rtt = None
        payload = MALFORMED_PLAINTEXT
    elif mode == "inflated":
        supplied_rtt = INFLATED_RTT_SECONDS
        payload = umsgpack.packb(supplied_rtt)
    elif mode == "fixed":
        if extra_rtt is None:
            raise ValueError("probe mode 'fixed' requires --extra-rtt")
        supplied_rtt = float(extra_rtt)
        payload = umsgpack.packb(supplied_rtt)
    else:
        supplied_rtt = float(max(link.rtt or 0.01, 0.01))
        payload = umsgpack.packb(supplied_rtt)
    packet = RNS.Packet(link, payload, context=RNS.Packet.LRRTT, create_receipt=False)

    if mode == "corrupt":
        original = RNS.Link.encrypt
        state = {"armed": True}

        def tampering_encrypt(self: object, plaintext: bytes) -> bytes:
            token = original(self, plaintext)
            if state["armed"]:
                state["armed"] = False
                return corrupt_token(token)
            return token

        RNS.Link.encrypt = tampering_encrypt
        try:
            accepted = packet.send()
        finally:
            RNS.Link.encrypt = original
        log.log("fresh_lrrtt_probe_sent", link_id=lid, mode=mode, send_rejected=(accepted is False),
                ciphertext_tampered=True, authentic_token=False, replay=False,
                supplied_rtt=supplied_rtt, captured_transmissions=None)
        return

    accepted, captured = send_capture(RNS, packet)
    log.log("fresh_lrrtt_probe_sent", link_id=lid, mode=mode, send_rejected=(accepted is False),
            ciphertext_tampered=False, authentic_token=True, replay=False,
            supplied_rtt=supplied_rtt, captured_transmissions=len(captured))

    if mode == "replay":
        if not captured:
            log.log("replay_failed", link_id=lid, reason="no outgoing transmission captured")
            return
        interface, raw = captured[-1]
        time.sleep(REPLAY_DELAY_SECONDS)
        RNS.Transport.transmit(interface, raw)
        log.log("replayed_lrrtt_sent", link_id=lid, identical_bytes=True, bytes=len(raw),
                transmissions_captured=len(captured))


def client(RNS: object, umsgpack: object, args: argparse.Namespace, log: EventWriter) -> None:
    RNS.Reticulum(str(args.config))
    if args.trace_file:
        install_packet_trace(RNS, Path(args.trace_file), "client")
        log.log("packet_trace_installed", path=str(args.trace_file), sync_inbound=False)
    log.log("interfaces_initialised", interfaces=interface_snapshot(RNS))
    if not await_usable_interface(RNS, args.interface_timeout):
        log.log(
            "tcp_interface_offline",
            diagnosis="no online outgoing interface within the interface timeout; the TCP connection to the server was never established",
            interfaces=interface_snapshot(RNS),
        )
        raise TimeoutError("No online RNS interface before bounded timeout")
    log.log("tcp_interface_online", interfaces=interface_snapshot(RNS))

    target_hash = destination_hash(args.destination)
    log.log("path_search_started", target=args.destination, known_paths=known_path_hashes(RNS))

    deadline = time.monotonic() + args.path_timeout
    last_heartbeat = 0.0
    while not RNS.Transport.has_path(target_hash) and time.monotonic() < deadline:
        RNS.Transport.request_path(target_hash)
        now = time.monotonic()
        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            log.log(
                "path_search_waiting",
                target=args.destination,
                known_paths=known_path_hashes(RNS),
                interfaces=interface_snapshot(RNS),
            )
            last_heartbeat = now
        time.sleep(PATH_REQUEST_INTERVAL)

    if not RNS.Transport.has_path(target_hash):
        known = known_path_hashes(RNS)
        if not known:
            diagnosis = "no announces were received on any interface; the destination never announced, or announces never reached this instance"
        else:
            diagnosis = "announces were received, but none for the requested destination hash; the supplied hash belongs to a different or earlier server run"
        log.log(
            "path_discovery_failed",
            target=args.destination,
            diagnosis=diagnosis,
            known_paths=known,
            interfaces=interface_snapshot(RNS),
        )
        raise TimeoutError("Path not available before bounded timeout")

    hops = RNS.Transport.hops_to(target_hash)
    log.log("path_discovered", target=args.destination, hops=hops, known_paths=known_path_hashes(RNS))

    identity = RNS.Identity.recall(target_hash)
    if identity is None:
        log.log(
            "peer_identity_unavailable",
            target=args.destination,
            diagnosis="a path is known, but the peer identity could not be recalled; the announce may not have been received in full",
        )
        raise RuntimeError("Peer identity unavailable, refusing to connect")
    destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, ASPECT)
    perturber = PacketPerturber(mode=args.perturb, delay=args.perturb_delay,
                                dup_delay=args.dup_delay)
    if args.perturb != "none":
        install_perturber(RNS, perturber)
        log.log("perturbation_armed", mode=args.perturb, delay=args.perturb_delay,
                dup_delay=args.dup_delay, target="first establishment LRRTT")
    established = threading.Event()
    closed = threading.Event()
    client_callbacks = 0

    def on_established(link: object) -> None:
        nonlocal client_callbacks
        client_callbacks += 1
        log.log("client_established", link_id=linkid(link), status=link.status, callback_number=client_callbacks)
        established.set()

    def on_closed(link: object) -> None:
        log.log("client_link_closed", link_id=linkid(link), status=link.status)
        closed.set()

    link = RNS.Link(destination, established_callback=on_established, closed_callback=on_closed)
    log.log("client_link_requested", link_id=linkid(link))
    if not established.wait(args.link_timeout):
        log.log(
            "link_establishment_failed",
            link_id=linkid(link),
            status=link.status,
            link_closed=closed.is_set(),
            diagnosis="path was known and the link request was sent, but the link never became active",
        )
        raise TimeoutError("Link did not establish before bounded timeout")

    for index in range(args.data_packets):
        data_packet = RNS.Packet(link, DATA_PAYLOAD.format(index=index).encode("utf-8"))
        sent = data_packet.send()
        log.log("client_data_sent", link_id=linkid(link), index=index, send_rejected=(sent is False),
                status=link.status)

    # Allow the genuine RTT to be processed at the server before probing. The delay sets the
    # link's age at probe arrival, and the responder adopts rtt = max(measured_age, supplied),
    # so it bounds the smallest deadline a probe can impose.
    time.sleep(args.probe_delay)
    if args.probe_mode == "none":
        log.log("control_no_probe", link_id=linkid(link))
    else:
        if link.status != RNS.Link.ACTIVE:
            log.log(
                "probe_refused",
                link_id=linkid(link),
                status=link.status,
                diagnosis="refusing probe, link is not ACTIVE",
            )
            raise RuntimeError("Refusing probe: link not ACTIVE")
        send_probe(RNS, umsgpack, link, args.probe_mode, log, extra_rtt=args.extra_rtt)

    # Signal readiness for orchestrator-controlled silence (E2): the client stays alive and
    # sends nothing, so the responder's own watchdog decides the link's fate.
    log.log("client_ready_for_pause", link_id=linkid(link), hold_seconds=args.hold_seconds,
            status=link.status)
    if args.hold_seconds > 0:
        time.sleep(args.hold_seconds)
    else:
        time.sleep(OBSERVATION_SECONDS)
    log.log("client_finished_observation", link_id=linkid(link), client_callback_count=client_callbacks,
            status=link.status)
    if args.perturb != "none":
        log.log("perturbation_events", mode=args.perturb, events=perturber.events,
                consumed=perturber.consumed)
    if args.no_teardown:
        log.log("client_skipped_teardown", link_id=linkid(link), status=link.status)
    else:
        link.teardown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded loopback-only RNS T0/T2 link research pilot")
    parser.add_argument("role", choices=("server", "client"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--destination", help="Server destination hash as printed in the server log")
    parser.add_argument("--destination-file", help="File containing the server destination hash (server --destination-out)")
    parser.add_argument("--destination-out", help="Server only: write the destination hash to this file for the client")
    parser.add_argument("--identity", help="Server only: load this identity file, or create it if absent, so the destination hash is stable")
    parser.add_argument("--probe-once", action="store_true", help="Send ONE additional new LRRTT after ACTIVE, T2 only")
    parser.add_argument("--probe-mode", choices=PROBE_MODES, help="Client probe mode; defaults to fresh with --probe-once, else none")
    parser.add_argument("--extra-rtt", type=float, help="Client only: RTT value supplied by probe mode 'fixed' (E2)")
    parser.add_argument("--probe-delay", type=float, default=PROBE_SETTLE_SECONDS,
                        help="Client only: seconds to wait after establishment before probing (E2)")
    parser.add_argument("--hardening", choices=HARDENING_MODES, default="off",
                        help="Server only: runtime responder-rtt hardening candidate")
    parser.add_argument("--app-mode", choices=APP_MODES, default="counting",
                        help="Server only: establishment-callback handler shape (E1)")
    parser.add_argument("--observe-seconds", type=float, default=0.0,
                        help="Server only: behavioural observation window for link-state transitions (E2)")
    parser.add_argument("--perturb", choices=PERTURB_MODES, default="none",
                        help="Client only: one-shot perturbation of the establishment LRRTT (E3)")
    parser.add_argument("--perturb-delay", type=float, default=PERTURB_DELAY_SECONDS,
                        help="Client only: how long mode 'delay' withholds the establishment LRRTT")
    parser.add_argument("--dup-delay", type=float, default=0.0,
                        help="Client only: time between the two identical copies in mode 'dup'")
    parser.add_argument("--data-packets", type=int, default=0,
                        help="Client only: benign DATA packets sent right after establishment")
    parser.add_argument("--hold-seconds", type=float, default=0.0,
                        help="Client only: stay alive and silent for this long before finishing")
    parser.add_argument("--no-teardown", action="store_true",
                        help="Client only: exit without tearing the link down")
    parser.add_argument("--trial-label", help="Trial label recorded in every event; defaults to T2 with a probe else T0")
    parser.add_argument("--trace-file", type=Path,
                        help="Both roles: write the observer-only inbound/outbound ordering trace here")
    parser.add_argument("--sync-inbound", action="store_true",
                        help="Server only: mechanism control, process inbound packets inline (USE_INBOUND_QUEUE=no)")
    parser.add_argument("--path-timeout", type=float, default=25.0)
    parser.add_argument("--link-timeout", type=float, default=25.0)
    parser.add_argument("--interface-timeout", type=float, default=15.0, help="Seconds to wait for an online TCP interface")
    args = parser.parse_args()
    if not (args.config / "config").exists():
        parser.error("config directory must contain file named 'config'; run setup_loopback.py first")
    conf = (args.config / "config").read_text(encoding="utf-8")
    # Guard against accidental use against the public network. Deliberately strict.
    if "127.0.0.1" not in conf or "share_instance = no" not in conf or "AutoInterface" in conf:
        parser.error("refusing non-loopback or shared-instance configuration")
    if args.role == "client":
        if args.destination_file:
            try:
                args.destination = Path(args.destination_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                parser.error("could not read --destination-file: {exc}".format(exc=exc))
        if not args.destination:
            parser.error("client requires --destination or --destination-file")
        try:
            destination_hash(args.destination)
        except ValueError as exc:
            parser.error(str(exc))
    if args.probe_mode is None:
        args.probe_mode = "fresh" if args.probe_once else "none"
    if args.probe_once and args.probe_mode != "fresh":
        parser.error("--probe-once cannot be combined with --probe-mode {mode}".format(mode=args.probe_mode))
    if args.role == "server" and args.probe_mode != "none":
        parser.error("--probe-once and --probe-mode are client-only")
    if args.role == "client" and args.hardening != "off":
        parser.error("--hardening is server-only")
    if args.role == "client" and (args.app_mode != "counting" or args.observe_seconds > 0):
        parser.error("--app-mode and --observe-seconds are server-only")
    if args.role == "server" and (args.perturb != "none" or args.extra_rtt is not None
                                  or args.data_packets or args.hold_seconds or args.no_teardown):
        parser.error("--perturb, --extra-rtt, --data-packets, --hold-seconds and --no-teardown are client-only")
    if args.probe_mode == "fixed" and args.extra_rtt is None:
        parser.error("--probe-mode fixed requires --extra-rtt")
    if args.extra_rtt is not None and args.extra_rtt < 0:
        parser.error("--extra-rtt must not be negative")
    if args.probe_delay < 0:
        parser.error("--probe-delay must not be negative")
    if args.dup_delay < 0:
        parser.error("--dup-delay must not be negative")
    if args.observe_seconds < 0 or args.hold_seconds < 0 or args.data_packets < 0:
        parser.error("--observe-seconds, --hold-seconds and --data-packets must not be negative")
    if args.role == "client" and (args.destination_out or args.identity):
        parser.error("--destination-out and --identity are server-only")
    if args.role == "client" and args.sync_inbound:
        parser.error("--sync-inbound is server-only")
    if args.path_timeout <= 0 or args.link_timeout <= 0 or args.interface_timeout <= 0:
        parser.error("timeouts must be positive")
    log = EventWriter(args.events, args.role, args.trial_label or ("T2" if args.probe_mode != "none" else "T0"))
    try:
        import importlib.metadata
        import RNS
        from RNS.vendor import umsgpack
    except ImportError as exc:
        raise SystemExit("RNS not installed in current interpreter: {exc}; use an isolated environment with rns==1.5.7".format(exc=exc)) from exc
    installed_version = importlib.metadata.version("rns")
    if installed_version != "1.5.7":
        raise SystemExit("Refusing experiment on RNS {version}, target is 1.5.7".format(version=installed_version))
    log.log(
        "process_started",
        config_dir=str(args.config.resolve()),
        rns_module=str(RNS.__file__),
        rns_version=installed_version,
        python=sys.version.split()[0],
        probe_mode=args.probe_mode,
        extra_rtt=args.extra_rtt,
        hardening=args.hardening,
        app_mode=args.app_mode,
        observe_seconds=args.observe_seconds,
        perturb=args.perturb,
        data_packets=args.data_packets,
        hold_seconds=args.hold_seconds,
        no_teardown=args.no_teardown,
        trace_file=str(args.trace_file) if args.trace_file else None,
        sync_inbound=args.sync_inbound,
    )
    try:
        if args.role == "server":
            server(RNS, args, log)
        else:
            client(RNS, umsgpack, args, log)
    except Exception as exc:
        log.log("run_failed", reason=repr(exc))
        raise


if __name__ == "__main__":
    main()
