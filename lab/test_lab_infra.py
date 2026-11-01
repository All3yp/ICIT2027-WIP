#!/usr/bin/env python3
"""Unit tests for the experimental infrastructure (no RNS runtime required).

Run: uv run pytest lab/test_lab_infra.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB_DIR))

import link_lab  # noqa: E402
import perturb  # noqa: E402
import relay  # noqa: E402
import run_trial  # noqa: E402
import summarize_trials  # noqa: E402
from app_handlers import build_handler  # noqa: E402
from deep_trace import TraceBuffer  # noqa: E402
from perturb import PacketPerturber  # noqa: E402
from setup_loopback import CLIENT, SERVER  # noqa: E402


def test_destination_hash_requires_32_hex_chars():
    link_lab.destination_hash("0" * 32)
    with pytest.raises(ValueError):
        link_lab.destination_hash("0" * 31)
    with pytest.raises(ValueError):
        link_lab.destination_hash("z" * 32)


def test_config_templates_are_loopback_only():
    rendered_server = SERVER.format(port=42500)
    rendered_client = CLIENT.format(port=42500)
    for rendered in (rendered_server, rendered_client):
        assert "127.0.0.1" in rendered
        assert "share_instance = no" in rendered
        assert "AutoInterface" not in rendered


def test_port_is_free_on_unbound_high_port():
    assert run_trial.port_is_free(45999) is True


def test_summarize_trials_counts_callbacks(tmp_path):
    def manifest(name, callbacks):
        d = tmp_path / name
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({
            "trial": "T2",
            "run_dir": name,
            "status": "OK",
            "client_active_confirmed": True,
            "client_callback_count": 1,
            "server_established_count": sum(callbacks.values()),
            "server_callbacks_by_link": callbacks,
            "correlated_link_ids": list(callbacks),
            "link_latency_seconds": 0.002,
            "probe_sent": True,
            "run_failed_events": [],
        }), encoding="utf-8")

    manifest("T2_a", {"aa": 2})
    manifest("T2_b", {"bb": 2})
    manifests = sorted(tmp_path.glob("*/manifest.json"))
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in manifests]
    maxes = [max(m["server_callbacks_by_link"].values()) for m in rows]
    assert maxes == [2, 2]


def test_corrupt_token_flips_only_the_trailing_hmac_byte():
    token = bytes(range(52))
    damaged = link_lab.corrupt_token(token)
    assert len(damaged) == len(token)
    assert damaged[:-1] == token[:-1]
    assert damaged[-1] != token[-1]


def test_corrupt_token_rejects_short_input():
    with pytest.raises(ValueError):
        link_lab.corrupt_token(b"\x00")


def test_probe_and_hardening_vocabularies_are_centralized():
    assert link_lab.PROBE_MODES == ("none", "fresh", "fixed", "inflated", "replay", "corrupt", "malformed")
    assert link_lab.HARDENING_MODES == ("off", "guarded-rtt")
    assert link_lab.GUARDED_HARDENING in link_lab.HARDENING_MODES
    assert link_lab.INFLATED_RTT_SECONDS > link_lab.PROBE_SETTLE_SECONDS * 1000
    assert perturb.PERTURB_MODES == ("none", "dup", "drop", "delay", "reorder", "retransmit")


def test_nonidempotent_handler_duplicates_work_and_trips_its_invariant():
    _state, handler = build_handler("nonidempotent")
    handler("aa")
    fields = handler("aa")
    assert fields["app_sessions_created"] == 2
    assert fields["app_accounting_units"] == 2
    assert fields["app_invariant_violations"] == 1
    assert fields["app_sessions_for_link"] == {"aa": 2}


def test_idempotent_handler_absorbs_the_repeat_notification():
    _state, handler = build_handler("idempotent")
    handler("aa")
    fields = handler("aa")
    assert fields["app_sessions_created"] == 1
    assert fields["app_accounting_units"] == 1
    assert fields["app_redundant_calls"] == 1
    assert fields["app_invariant_violations"] == 0
    assert fields["app_sessions_for_link"] == {"aa": 1}


def test_counting_handler_matches_the_earlier_dataset_semantics():
    _state, handler = build_handler("counting")
    handler("aa")
    fields = handler("aa")
    assert fields["app_callbacks"] == 2
    assert fields["app_sessions_created"] == 0


def test_build_handler_rejects_unknown_mode():
    with pytest.raises(ValueError):
        build_handler("does-not-exist")


def test_status_name_maps_rns_link_states():
    assert [link_lab.status_name(value) for value in range(5)] == [
        "PENDING", "HANDSHAKE", "ACTIVE", "STALE", "CLOSED"]
    assert link_lab.status_name("weird") == "weird"


def test_time_to_status_measures_the_behavioural_delay():
    events = [
        {"event": "server_established", "callback_number": 1,
         "timestamp_utc": "2026-10-21T00:00:00.000000+00:00"},
        {"event": "server_status", "status_name": "ACTIVE",
         "timestamp_utc": "2026-10-21T00:00:00.100000+00:00"},
        {"event": "server_status", "status_name": "STALE",
         "timestamp_utc": "2026-10-21T00:00:10.500000+00:00"},
    ]
    assert link_lab.time_to_status(events, "STALE") == 10.5
    assert link_lab.time_to_status(events, "CLOSED") is None


class _FakeTimer:
    instances: list = []

    def __init__(self, interval, function, args=(), kwargs=None):
        self.interval = interval
        self.function = function
        self.daemon = False
        self.started = False
        _FakeTimer.instances.append(self)

    def start(self):
        self.started = True

    def fire(self):
        self.function()


def test_perturber_drop_suppresses_the_establishment_lrrtt():
    sent: list = []
    perturber = PacketPerturber(mode="drop")
    handled = perturber.handle_outbound(True, "iface", b"lrrtt", lambda i, r: sent.append(r))
    assert handled is True
    assert sent == []
    assert perturber.consumed is True
    assert perturber.events == [{"perturbation": "drop", "dropped_bytes": 5}]


def test_perturber_dup_transmits_the_identical_bytes_twice():
    sent: list = []
    perturber = PacketPerturber(mode="dup")
    assert perturber.handle_outbound(True, "iface", b"lrrtt", lambda i, r: sent.append(r)) is True
    assert sent == [b"lrrtt", b"lrrtt"]


def test_perturber_retransmit_repeats_identical_bytes_after_a_delay(monkeypatch):
    monkeypatch.setattr(perturb.threading, "Timer", _FakeTimer)
    _FakeTimer.instances = []
    sent: list = []
    perturber = PacketPerturber(mode="retransmit", retransmit_delay=0.3)
    perturber.handle_outbound(True, "iface", b"lrrtt", lambda i, r: sent.append(r))
    assert sent == [b"lrrtt"]
    assert _FakeTimer.instances[-1].interval == 0.3
    _FakeTimer.instances[-1].fire()
    assert sent == [b"lrrtt", b"lrrtt"]


def test_perturber_delay_withholds_then_releases(monkeypatch):
    monkeypatch.setattr(perturb.threading, "Timer", _FakeTimer)
    _FakeTimer.instances = []
    sent: list = []
    perturber = PacketPerturber(mode="delay", delay=2.0)
    perturber.handle_outbound(True, "iface", b"lrrtt", lambda i, r: sent.append(r))
    assert sent == []
    assert _FakeTimer.instances[-1].interval == 2.0
    _FakeTimer.instances[-1].fire()
    assert sent == [b"lrrtt"]


def test_perturber_reorder_releases_after_the_next_packet():
    sent: list = []
    perturber = PacketPerturber(mode="reorder")
    perturber.handle_outbound(True, "iface", b"lrrtt", lambda i, r: sent.append(r))
    assert sent == []
    perturber.handle_followup(is_lrrtt=False, transmit=lambda i, r: sent.append(r))
    assert sent == [b"lrrtt"]
    assert perturber.held is None


def test_perturber_is_one_shot_and_ignores_other_traffic():
    sent: list = []
    perturber = PacketPerturber(mode="dup")
    assert perturber.handle_outbound(False, "iface", b"data", lambda i, r: sent.append(r)) is False
    perturber.handle_outbound(True, "iface", b"lrrtt", lambda i, r: sent.append(r))
    assert sent == [b"lrrtt", b"lrrtt"]
    assert perturber.handle_outbound(True, "iface", b"probe", lambda i, r: sent.append(r)) is False
    assert sent == [b"lrrtt", b"lrrtt"]


def test_perturber_rejects_unknown_mode():
    with pytest.raises(ValueError):
        PacketPerturber(mode="teleport")


class _StubLink:
    status = 2
    rtt = 0.00125
    expected_hops = 1
    establishment_rate = 1234.5
    keepalive = 5.0
    stale_time = 10.0
    activated_at = 1000.0

    def get_age(self):
        return 0.5


def test_link_state_reports_responder_visible_fields():
    state = link_lab.link_state(_StubLink())
    assert state == {
        "status": 2,
        "status_name": "ACTIVE",
        "rtt": 0.00125,
        "expected_hops": 1,
        "establishment_rate": 1234.5,
        "keepalive": 5.0,
        "stale_time": 10.0,
        "activated_at": 1000.0,
        "age_seconds": 0.5,
    }


def test_link_state_tolerates_missing_activation():
    class NeverActivated:
        status = 1
        rtt = None
        expected_hops = None
        establishment_rate = None
        keepalive = None
        stale_time = None
        activated_at = None

        def get_age(self):
            return None

    state = link_lab.link_state(NeverActivated())
    assert state["rtt"] is None
    assert state["status_name"] == "HANDSHAKE"
    assert state["age_seconds"] is None


def test_malformed_probe_payload_is_reserved_msgpack():
    from RNS.vendor import umsgpack

    # The malformed-probe premise: a validly encrypted LRRTT carrying this byte still
    # decrypts, and then fails during unpacking inside the responder RTT handler.
    with pytest.raises(umsgpack.ReservedCodeException):
        umsgpack.unpackb(link_lab.MALFORMED_PLAINTEXT)
    assert isinstance(umsgpack.unpackb(umsgpack.packb(0.001)), float)


def test_summarize_trials_groups_run_variants(tmp_path):
    d = tmp_path / "T2h_run"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({
        "trial": "T2h",
        "run_dir": "T2h_run",
        "status": "OK",
        "probe_mode": "fresh",
        "hardening": "guarded-rtt",
        "client_active_confirmed": True,
        "client_callback_count": 1,
        "server_established_count": 1,
        "server_callbacks_by_link": {"aa": 1},
        "correlated_link_ids": ["aa"],
        "hardening_rtt_rejected": 1,
        "server_link_closed_events": 0,
        "server_callback_states": [{"callback_number": 1, "status": 2}],
        "run_failed_events": [],
    }), encoding="utf-8")

    summary = summarize_trials.build_summary(sorted(tmp_path.glob("*/manifest.json")))
    assert summary["by_trial"]["T2h"]["variants"] == ["fresh/guarded-rtt"]
    assert summary["rows"][0]["hardening_rtt_rejected"] == 1


def test_relay_reassembles_hdlc_frames_byte_for_byte():
    payload = b"\x00\x01" + bytes([relay.FLAG]) + b"abc" + bytes([relay.ESC])
    escaped = b"\x00\x01" + bytes([relay.ESC, relay.FLAG ^ relay.ESC_MASK]) + b"abc" \
        + bytes([relay.ESC, relay.ESC ^ relay.ESC_MASK])
    stream = bytes([relay.FLAG]) + escaped + bytes([relay.FLAG])
    frames, remainder = relay.split_frames(stream)
    # The closing flag is retained: in this framing it can open the next frame.
    assert remainder == bytes([relay.FLAG])
    assert len(frames) == 1
    assert frames[0][0] == stream
    assert frames[0][1] == payload


def test_relay_holds_a_partial_frame_until_it_completes():
    full = bytes([relay.FLAG]) + b"payload" + bytes([relay.FLAG])
    frames, remainder = relay.split_frames(full + bytes([relay.FLAG]) + b"pay")
    assert len(frames) == 1
    assert remainder == bytes([relay.FLAG]) + b"pay"
    frames, remainder = relay.split_frames(remainder + b"load" + bytes([relay.FLAG]))
    assert frames[0][1] == b"payload"
    assert remainder == bytes([relay.FLAG])


def _link_packet(context: int, header_two: bool, length: int = 83) -> bytes:
    head = bytearray(length)
    head[0] = relay.HEADER_2_BIT if header_two else 0
    offset = 2 * relay.HASH_LEN + 2 if header_two else relay.HASH_LEN + 2
    head[offset] = context
    return bytes(head)


def test_relay_recognises_lrrtt_in_both_header_formats():
    assert relay.is_lrrtt(_link_packet(0xFE, header_two=False)) is True
    assert relay.is_lrrtt(_link_packet(0xFE, header_two=True)) is True
    assert relay.is_lrrtt(_link_packet(0xFA, header_two=False)) is False
    assert relay.is_lrrtt(b"\x00\x00") is False


def test_trace_buffer_writes_anchor_and_records(tmp_path):
    buffer = TraceBuffer(tmp_path / "trace.jsonl", "server")
    buffer.record("filter", hash="aa", passed=True)
    buffer.record("hash_add", hash="aa", already_present=False)
    buffer.flush(final=True)
    lines = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    anchor = lines[0]
    assert anchor["record"] == "anchor"
    assert anchor["role"] == "server"
    assert [line["event"] for line in lines[1:]] == ["filter", "hash_add"]
    assert lines[1]["t_ns"] <= lines[2]["t_ns"]


def _write_trace_run(root: Path) -> Path:
    run = root / "E3dupQ0_test"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "trial": "E3dupQ0",
        "status": "OK",
        "server_callbacks_by_link": {"aa": 2},
        "dup_delay": 0.0,
        "sync_inbound": False,
        "perturbation_events": [{"perturbation": "dup", "bytes": 83}],
        "relay": {"enabled": False},
    }), encoding="utf-8")
    shared = {
        "recv": [{"event": "recv", "t_ns": 900_000, "bytes": 170}],
        "filter": [
            {"event": "filter", "t_ns": 1_000_000, "hash": "aa", "context": 254,
             "present": False, "passed": True},
            {"event": "filter", "t_ns": 1_020_000, "hash": "aa", "context": 254,
             "present": False, "passed": True},
        ],
        "enqueue": [
            {"event": "enqueue", "t_ns": 1_010_000, "hash": "aa", "queue_depth_after": 1},
            {"event": "enqueue", "t_ns": 1_025_000, "hash": "aa", "queue_depth_after": 2},
        ],
        "dequeue": [
            {"event": "dequeue", "t_ns": 1_030_000, "hash": "aa"},
            {"event": "dequeue", "t_ns": 1_080_000, "hash": "aa"},
        ],
        "inbound_entry": [
            {"event": "inbound_entry", "t_ns": 1_031_000, "hash": "aa", "present": False},
            {"event": "inbound_entry", "t_ns": 1_081_000, "hash": "aa", "present": True},
        ],
        "hash_add": [
            {"event": "hash_add", "t_ns": 1_060_000, "hash": "aa", "already_present": False},
            {"event": "hash_add", "t_ns": 1_090_000, "hash": "aa", "already_present": True},
        ],
        "link_receive": [
            {"event": "link_receive", "t_ns": 1_070_000, "hash": "aa", "status": 1},
            {"event": "link_receive", "t_ns": 1_095_000, "hash": "aa", "status": 2},
        ],
    }
    server = []
    for index in range(2):
        server.append(shared["recv"][0] if index == 0 else {"event": "recv", "t_ns": 1_015_000,
                                                           "bytes": 85})
        server.extend([shared["filter"][index], shared["enqueue"][index]])
        if index == 0:
            server.extend([shared["dequeue"][0], shared["inbound_entry"][0], shared["hash_add"][0],
                           shared["link_receive"][0]])
    server.extend([shared["dequeue"][1], shared["inbound_entry"][1], shared["hash_add"][1],
                   shared["link_receive"][1]])
    (run / "server_trace.jsonl").write_text(
        "\n".join(json.dumps(item) for item in server) + "\n", encoding="utf-8")
    (run / "client_trace.jsonl").write_text(
        "\n".join(json.dumps(item) for item in [
            {"event": "tx", "t_ns": 500_000, "bytes": 83},
            {"event": "tx", "t_ns": 530_000, "bytes": 83},
        ]) + "\n", encoding="utf-8")
    return run


def test_analyse_e3dup_separates_filter_and_enqueue_commit_windows(tmp_path):
    import analyse_e3dup

    run = _write_trace_run(tmp_path)
    row = analyse_e3dup.analyse_run(run)
    assert row["callbacks_per_link"] == 2
    assert row["lrrtt_frames_observed"] == 2
    assert row["filter_and_commit_window_us"] == 60.0
    assert row["enqueue_to_commit_us"] == 50.0
    assert row["second_filter_margin_us"] == 10.0
    assert row["arrival_separation_us"] == 20.0
    assert row["hash_committed_before_second_filter"] is False
    assert row["measured_send_separation_us"] == 30.0


def test_analyse_e3dup_groups_by_mechanism_and_separation(tmp_path):
    import analyse_e3dup

    _write_trace_run(tmp_path)
    table = analyse_e3dup.summarise([analyse_e3dup.analyse_run(_write_trace_run(tmp_path / "b"))])
    assert list(table) == ["sender:0.0"]
    assert table["sender:0.0"]["two_callbacks"] == 1
