#!/usr/bin/env python3
"""One-shot link-packet perturbation for the E3 robustness trials.

The initiator's establishment `LRRTT` is the packet that drives the responder's
establishment transition, so it is the packet whose loss, delay, duplication, reordering and
retransmission a fix has to survive. `PacketPerturber` applies exactly one such perturbation
to the **first** `LRRTT` the initiator transmits; every later packet (including the probes used
by the other trials) is passed through untouched.

The sending action is injected as a callback, so the logic is unit-testable without RNS.
"""
from __future__ import annotations

import threading

PERTURB_MODES = ("none", "dup", "drop", "delay", "reorder", "retransmit")
PERTURB_DELAY_SECONDS = 2.0
PERTURB_RETRANSMIT_DELAY_SECONDS = 0.3


class PacketPerturber:
    """Applies one perturbation to the first outbound `LRRTT`."""

    def __init__(self, mode: str = "none", delay: float = PERTURB_DELAY_SECONDS,
                 retransmit_delay: float = PERTURB_RETRANSMIT_DELAY_SECONDS,
                 dup_delay: float = 0.0):
        if mode not in PERTURB_MODES:
            raise ValueError(f"unknown perturbation {mode!r}, expected one of {PERTURB_MODES}")
        self.mode = mode
        self.delay = delay
        self.retransmit_delay = retransmit_delay
        self.dup_delay = dup_delay
        self.pending_context: tuple | None = None
        self.consumed = False
        self.held: tuple | None = None
        self.events: list[dict] = []

    def annotate(self, context: object, packet_type: object) -> None:
        """Record what the packet about to be transmitted actually is."""
        self.pending_context = (context, packet_type)

    def handle_outbound(self, is_lrrtt: bool, interface: object, raw: bytes, transmit) -> bool:
        """Apply the perturbation. Returns True when the caller must not also send."""
        if self.mode == "none" or not is_lrrtt or self.consumed:
            return False
        self.consumed = True

        if self.mode == "drop":
            self.events.append({"perturbation": "drop", "dropped_bytes": len(raw)})
            return True

        if self.mode == "dup":
            # Two copies of the SAME bytes. `dup_delay` separates them in time, which is what
            # distinguishes a same-window duplicate from a later replay: the receiver's
            # packet-hash filter only remembers a hash once the first copy has been processed.
            transmit(interface, raw)
            if self.dup_delay > 0:
                timer = threading.Timer(self.dup_delay, lambda: transmit(interface, raw))
                timer.daemon = True
                timer.start()
            else:
                transmit(interface, raw)
            self.events.append({"perturbation": "dup", "transmissions": 2, "bytes": len(raw),
                                "identical_bytes": True, "second_copy_delay_seconds": self.dup_delay})
            return True

        if self.mode == "retransmit":
            transmit(interface, raw)
            timer = threading.Timer(self.retransmit_delay, lambda: transmit(interface, raw))
            timer.daemon = True
            timer.start()
            self.events.append({"perturbation": "retransmit", "transmissions": 2,
                                "identical_bytes": True, "bytes": len(raw)})
            return True

        if self.mode == "delay":
            timer = threading.Timer(self.delay, lambda: transmit(interface, raw))
            timer.daemon = True
            timer.start()
            self.events.append({"perturbation": "delay", "delayed_seconds": self.delay,
                                "bytes": len(raw)})
            return True

        if self.mode == "reorder":
            self.held = (interface, raw)
            self.events.append({"perturbation": "reorder", "state": "holding", "bytes": len(raw)})
            return True

        return False

    def handle_followup(self, is_lrrtt: bool, transmit) -> None:
        """Release a held `LRRTT` immediately after the next non-LRRTT packet is sent."""
        if self.held is None or is_lrrtt:
            return
        interface, raw = self.held
        self.held = None
        transmit(interface, raw)
        self.events.append({"perturbation": "reorder", "state": "released_after_followup",
                            "bytes": len(raw)})
