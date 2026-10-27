#!/usr/bin/env python3
"""Observer-only instrumentation of the inbound packet path (E3 duplication mechanism).

The E3 duplication control showed that two byte-identical ``LRRTT`` frames produce two
responder callbacks when they are transmitted in one call, but only one when the second copy
is delayed. This module records the ordering of the events that decide that outcome:

  socket recv -> HDLC frame -> packet_filter -> inbound queue -> hash commit -> Link.receive
              -> rtt_packet -> link_established

Every wrapper is a pure observer: it evaluates no new branch, drops no packet and mutates no
RNS state. Timestamps come from ``time.perf_counter_ns()`` and are anchored once to the wall
clock, so ordering within a process is exact and comparable across the client and the server.

Records are buffered in memory and flushed by a background thread plus ``atexit``; writing a
JSONL line inside the filter would itself move the race being measured.
"""
from __future__ import annotations

import atexit
import json
import os
import socket
import threading
import time
from pathlib import Path

FLUSH_INTERVAL_SECONDS = 2.0
SHORT_HASH_BYTES = 8


class TraceBuffer:
    """Minimal-overhead record buffer.

    ``record`` runs on the packet path, so it does one clock read and one list append. Formatting
    and file I/O happen in the flusher.
    """

    def __init__(self, path: Path, role: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.role = role
        self.anchor_epoch_ns = time.time_ns()
        self.anchor_perf_ns = time.perf_counter_ns()
        self.records: list[tuple[int, str, int, dict]] = []
        self.thread_ident = threading.get_ident()
        self._finalized = False
        self._stop = threading.Event()
        self._write_anchor()
        self._flusher = threading.Thread(target=self._flush_loop, daemon=True)
        self._flusher.start()
        atexit.register(self.flush, True)

    def _write_anchor(self) -> None:
        anchor = {"record": "anchor", "role": self.role, "epoch_ns": self.anchor_epoch_ns,
                  "perf_ns": self.anchor_perf_ns, "pid": os.getpid()}
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(anchor) + "\n")

    def record(self, kind: str, **fields: object) -> None:
        tid = threading.get_ident()
        self.records.append((time.perf_counter_ns() - self.anchor_perf_ns, kind, tid, fields))

    # Compatibility alias so callers can use the EventWriter verb calling convention.
    log = record

    def _flush_loop(self) -> None:
        while not self._stop.wait(FLUSH_INTERVAL_SECONDS):
            self.flush()

    def flush(self, final: bool = False) -> None:
        if final:
            if self._finalized:
                return
            self._finalized = True
            self._stop.set()
        if not self.records:
            return
        pending, self.records = self.records, []
        names = {thread.ident: thread.name for thread in threading.enumerate()}
        lines = []
        for offset_ns, kind, tid, fields in pending:
            item = {"t_ns": offset_ns, "epoch_ns": self.anchor_epoch_ns + offset_ns,
                    "event": kind, "thread": names.get(tid, f"tid-{tid}")}
            item.update(fields)
            lines.append(json.dumps(item, default=str))
        if not lines:
            return
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")


def _short(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex()[: SHORT_HASH_BYTES * 2]
    return str(value)


def install(RNS: object, path: Path, role: str) -> TraceBuffer:
    """Install the observers. Must be called before the RNS instance is constructed."""
    buffer = TraceBuffer(path, role)
    buffer.record("trace_installed", role=role)

    if role == "client":
        original_transmit = RNS.Transport.__dict__["transmit"]

        def transmit(interface: object, raw: bytes) -> object:
            buffer.record("tx", bytes=len(raw), interface=str(interface),
                          head=_short(raw[:1]))
            return original_transmit(interface, raw)

        RNS.Transport.transmit = staticmethod(transmit)
        return buffer

    original_recv = socket.socket.recv

    def recv(sock_self: object, *args: object, **kwargs: object) -> bytes:
        data = original_recv(sock_self, *args, **kwargs)
        if data:
            buffer.record("recv", bytes=len(data))
        return data

    socket.socket.recv = recv

    original_filter = RNS.Transport.packet_filter
    original_add_hash = RNS.Transport.add_packet_hash
    original_inbound = RNS.Transport._inbound
    queue_class = type(RNS.Transport.inbound_queues)
    original_put = queue_class.put
    original_get = queue_class.get
    original_receive = RNS.Link.receive
    original_rtt = RNS.Link.rtt_packet

    def packet_filter(packet: object) -> bool:
        packet_hash = packet.packet_hash
        present = packet_hash in RNS.Transport.packet_hashlist
        present_prev = packet_hash in RNS.Transport.packet_hashlist_prev
        passed = original_filter(packet)
        buffer.record("filter", hash=_short(packet_hash), present=present,
                      present_prev=present_prev, passed=passed,
                      context=packet.context, packet_type=packet.packet_type,
                      destination=_short(packet.destination_hash), hops=packet.hops)
        return passed

    def add_packet_hash(packet_hash: bytes) -> None:
        already = packet_hash in RNS.Transport.packet_hashlist
        original_add_hash(packet_hash)
        buffer.record("hash_add", hash=_short(packet_hash), already_present=already,
                      hashlist_size=len(RNS.Transport.packet_hashlist))

    def inbound(packet: object) -> object:
        buffer.record("inbound_entry", hash=_short(packet.packet_hash),
                      present=packet.packet_hash in RNS.Transport.packet_hashlist,
                      context=packet.context, queue_depth=RNS.Transport.inbound_queues.qsize())
        return original_inbound(packet)

    def queue_put(queue_self: object, traffic_class: int, item: object,
                  block: bool = False, timeout: float | None = None) -> object:
        depth = queue_self.qsize()
        result = original_put(queue_self, traffic_class, item, block=block, timeout=timeout)
        buffer.record("enqueue", hash=_short(item.packet_hash), traffic_class=traffic_class,
                      queue_depth_before=depth, queue_depth_after=queue_self.qsize())
        return result

    def queue_get(queue_self: object, block: bool = True, timeout: float | None = None) -> object:
        item = original_get(queue_self, block=block, timeout=timeout)
        buffer.record("dequeue", hash=_short(item.packet_hash),
                      queue_depth_after=queue_self.qsize())
        return item

    def receive(link_self: object, packet: object) -> object:
        buffer.record("link_receive", link_id=_short(link_self.link_id), context=packet.context,
                      status=link_self.status, rx=link_self.rx)
        return original_receive(link_self, packet)

    def rtt_packet(link_self: object, packet: object) -> object:
        buffer.record("rtt_enter", link_id=_short(link_self.link_id), status=link_self.status,
                      rx=link_self.rx)
        result = original_rtt(link_self, packet)
        buffer.record("rtt_exit", link_id=_short(link_self.link_id), status=link_self.status,
                      rtt=getattr(link_self, "rtt", None))
        return result

    RNS.Transport.packet_filter = staticmethod(packet_filter)
    RNS.Transport.add_packet_hash = staticmethod(add_packet_hash)
    RNS.Transport._inbound = staticmethod(inbound)
    queue_class.put = queue_put
    queue_class.get = queue_get
    RNS.Link.receive = receive
    RNS.Link.rtt_packet = rtt_packet

    return buffer
