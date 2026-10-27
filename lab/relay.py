#!/usr/bin/env python3
"""Key-less on-path relay that duplicates one opaque link packet (adversary M2).

The relay terminates TCP on both sides, re-emits HDLC frames byte-for-byte, and never
imports RNS, never holds a link key and never decrypts anything. It recognises a link RTT
acknowledgement purely from the public header layout (HEADER_2, context byte 0xFE), which is
visible on the wire, and re-emits that frame either immediately or after a delay.

This is the packet-level capability of an on-path observer/replayer: it can copy and re-send
authenticated ciphertext, but it cannot produce a fresh ciphertext for the same link and it
cannot choose the plaintext.

Loopback only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import socket
import sys
import threading
import time

FLAG = 0x7E
ESC = 0x7D
ESC_MASK = 0x20
HEADER_2_BIT = 0b01000000
HASH_LEN = 16
LRRTT_CONTEXT = 0xFE


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def unescape(data: bytes) -> bytes:
    result = bytearray()
    escaped = False
    for byte in data:
        if escaped:
            result.append(byte ^ ESC_MASK)
            escaped = False
        elif byte == ESC:
            escaped = True
        else:
            result.append(byte)
    return bytes(result)


def split_frames(buffer: bytes) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """Split an HDLC byte stream into (raw frame including flags, unescaped payload).

    The closing flag of a frame is returned as part of the remainder, because in this stream
    format it is also the opening flag of the next frame. Callers must keep it.
    """
    frames = []
    while True:
        start = buffer.find(bytes([FLAG]))
        if start == -1:
            return frames, b""
        end = buffer.find(bytes([FLAG]), start + 1)
        if end == -1:
            return frames, buffer[start:]
        payload = unescape(buffer[start + 1:end])
        if payload:
            frames.append((buffer[start:end + 1], payload))
        buffer = buffer[end:]


def is_lrrtt(payload: bytes) -> bool:
    """Recognise a link RTT acknowledgement from its public header alone.

    A link packet sent by either endpoint uses HEADER_1 (destination field = link id); a
    transporting node re-emits it as HEADER_2 with an extra transport id. Both layouts put the
    context byte right after the hash field(s), so both are handled without any key material.
    """
    if len(payload) < 2:
        return False
    header_two = bool(payload[0] & HEADER_2_BIT)
    offset = 2 * HASH_LEN + 2 if header_two else HASH_LEN + 2
    return len(payload) > offset and payload[offset] == LRRTT_CONTEXT


class Recorder:
    def __init__(self, path: Path | None):
        self.path = path
        self.lock = threading.Lock()
        self.started_ns = time.perf_counter_ns()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: object) -> None:
        item = {"timestamp_utc": utc_now(), "event": event,
                "t_ns": time.perf_counter_ns() - self.started_ns, **fields}
        if self.path:
            with self.lock, self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(item, default=str) + "\n")


def pump(source: socket.socket, sink: socket.socket, direction: str, args: argparse.Namespace,
         record: Recorder) -> None:
    state = {"duplicated": False}
    buffer = b""
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            buffer += data
            frames, buffer = split_frames(buffer)
            for raw, payload in frames:
                duplicate_here = (direction == "c2s" and not state["duplicated"]
                                  and is_lrrtt(payload))
                if not duplicate_here:
                    sink.sendall(raw)
                    record.log("frame_forwarded", direction=direction, bytes=len(payload),
                               lrrtt=is_lrrtt(payload))
                    continue

                state["duplicated"] = True
                if args.dup_delay > 0:
                    sink.sendall(raw)
                    time.sleep(args.dup_delay)
                    sink.sendall(raw)
                else:
                    # One write carrying both copies: this is the cut-through case, where the
                    # duplicate reaches the receiver in the same read as the original. Logging
                    # happens after the write so it cannot widen the interval being measured.
                    sink.sendall(raw + raw)
                record.log("lrrtt_duplicated", direction=direction, bytes=len(payload),
                           duplicate_delay_seconds=args.dup_delay, key_material_used=False)
    except OSError as exc:
        record.log("pump_error", direction=direction, reason=repr(exc))
    finally:
        for sock in (source, sink):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Key-less on-path LRRTT duplicating relay (M2)")
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--upstream", type=int, required=True)
    parser.add_argument("--dup-delay", type=float, default=0.0,
                        help="seconds between the two emissions of the captured frame")
    parser.add_argument("--events", type=Path)
    args = parser.parse_args()
    if args.dup_delay < 0:
        parser.error("--dup-delay must not be negative")

    record = Recorder(args.events)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.listen))
    listener.listen(1)
    record.log("relay_listening", listen_port=args.listen, upstream_port=args.upstream,
               duplicate_delay_seconds=args.dup_delay)

    def stop(*_: object) -> None:
        record.log("relay_stopping")
        try:
            listener.close()
        finally:
            sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    client_socket, address = listener.accept()
    record.log("relay_client_accepted", peer=str(address))
    upstream_socket = socket.create_connection(("127.0.0.1", args.upstream), timeout=10)
    record.log("relay_upstream_connected", port=args.upstream)

    threads = [
        threading.Thread(target=pump, args=(client_socket, upstream_socket, "c2s", args, record),
                         daemon=True),
        threading.Thread(target=pump, args=(upstream_socket, client_socket, "s2c", args, record),
                         daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
