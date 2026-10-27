#!/usr/bin/env python3
"""Representative application handlers for the `link_established` callback (E1).

The security relevance of a duplicate establishment notification depends entirely on the
handler shape an application uses, so two shapes are modelled side by side:

* `nonidempotent` - one session record and one accounting unit per callback, plus the
  application's own invariant "at most one session per link". A second callback therefore
  duplicates work and trips that invariant.
* `idempotent`   - records keyed by `link_id`; a second callback is a no-op that is counted
  as a redundant notification.

`counting` reproduces the handler used by the earlier T0/T2 trials, so the new runs stay
comparable with the existing dataset.

The handlers perform no I/O and hold only counters, so the effect is measurable without
pretending to model a real deployment.
"""
from __future__ import annotations

from dataclasses import dataclass, field

APP_MODES = ("counting", "nonidempotent", "idempotent")


@dataclass
class AppState:
    """Observable state of the handler, reported on every callback."""

    handler: str
    callbacks: int = 0
    sessions_created: int = 0
    accounting_units: int = 0
    redundant_calls: int = 0
    invariant_violations: int = 0
    per_link: dict = field(default_factory=dict)

    def fields(self) -> dict:
        return {
            "handler": self.handler,
            "app_callbacks": self.callbacks,
            "app_sessions_created": self.sessions_created,
            "app_accounting_units": self.accounting_units,
            "app_redundant_calls": self.redundant_calls,
            "app_invariant_violations": self.invariant_violations,
            "app_sessions_for_link": dict(self.per_link),
        }


def build_handler(mode: str) -> tuple[AppState, callable]:
    """Return (state, handler) where handler(link_id) -> dict of event fields."""
    if mode not in APP_MODES:
        raise ValueError(f"unknown app mode {mode!r}, expected one of {APP_MODES}")

    state = AppState(handler=mode)

    def counting(link_id: str) -> dict:
        state.callbacks += 1
        state.per_link[link_id] = state.per_link.get(link_id, 0) + 1
        return state.fields()

    def nonidempotent(link_id: str) -> dict:
        # One session record + one accounting unit per callback: this is what a handler that
        # allocates a session, registers a peer, or bills for a connection does.
        state.callbacks += 1
        state.sessions_created += 1
        state.accounting_units += 1
        state.per_link[link_id] = state.per_link.get(link_id, 0) + 1
        if state.per_link[link_id] > 1:
            state.invariant_violations += 1
        return state.fields()

    def idempotent(link_id: str) -> dict:
        # Records are keyed by link_id, so a repeat notification cannot create a second record.
        state.callbacks += 1
        if link_id in state.per_link:
            state.redundant_calls += 1
        else:
            state.per_link[link_id] = 1
            state.sessions_created += 1
            state.accounting_units += 1
        return state.fields()

    handler = {"counting": counting, "nonidempotent": nonidempotent, "idempotent": idempotent}[mode]
    return state, handler
