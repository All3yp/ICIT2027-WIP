#!/usr/bin/env python3
"""Unit tests for the multi-node feasibility topology (no RNS runtime required).

Run: uv run pytest lab/test_multinode_infra.py
"""
from __future__ import annotations

import sys
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB_DIR))

import analyse_multinode  # noqa: E402
import run_multinode  # noqa: E402


def test_topology_configs_are_loopback_only_and_transport_is_confined_to_the_hub():
    hub = run_multinode.HUB_CONFIG.format(port=44700)
    spoke = run_multinode.SPOKE_CONFIG.format(port=44700)
    for rendered in (hub, spoke):
        assert "127.0.0.1" in rendered
        assert "share_instance = no" in rendered
        assert "AutoInterface" not in rendered
    assert "enable_transport = yes" in hub
    assert "enable_transport = no" in spoke


def test_node_roles_and_conditions_are_centralized():
    assert run_multinode.NODES == ("hub", "h1", "h2", "h3", "adversary")
    assert run_multinode.CONDITIONS == ("baseline", "benign", "unknown", "announce")
    assert analyse_multinode.HONEST_NODES == ("h2", "h3")


def test_analyse_multinode_aggregates_inside_the_window():
    row = {
        "run": "unknown_x",
        "condition": "unknown",
        "nodes": {
            "h2": {"inside": {"attempts": 4, "successes": 3, "success_rate": 0.75,
                              "latency_median_ms": 2.0, "latency_p95_ms": 3.0,
                              "latency_max_ms": 4.0, "path_lost_events": 0},
                   "outside": {"attempts": 6, "successes": 6, "success_rate": 1.0,
                               "latency_median_ms": 1.8, "latency_p95_ms": 2.0,
                               "latency_max_ms": 2.4, "path_lost_events": 0}},
        },
        "hub": {"samples_inside": 12, "max_queue_depth": 0, "cpu_seconds_inside": 0.04,
                "rx_packets_inside": 120, "path_table_max": 1},
        "adversary": {"mode": "unknown", "sent": 120},
    }
    table = analyse_multinode.summarise([row])
    assert table["unknown"]["attempts_in_window"] == 4
    assert table["unknown"]["success_rate"] == 0.75
    assert table["unknown"]["adversary_sent"] == [120]
    assert table["unknown"]["hub_max_queue_depth"] == [0]
