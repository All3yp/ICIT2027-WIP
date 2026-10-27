#!/usr/bin/env python3
"""Write minimal isolated local-only Reticulum configurations (no networking action)."""
from __future__ import annotations
import argparse
from pathlib import Path

SERVER = """[reticulum]
enable_transport = no
share_instance = no

[interfaces]
  [[Research Loopback Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
"""
CLIENT = """[reticulum]
enable_transport = no
share_instance = no

[interfaces]
  [[Research Loopback Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parent / "runtime")
    parser.add_argument("--port", type=int, default=42424)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    for role, config in (("server", SERVER), ("client", CLIENT)):
        directory = args.root / role
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "config"
        if target.exists():
            raise SystemExit(f"Refusing to overwrite existing config: {target}")
        target.write_text(config.format(port=args.port), encoding="utf-8")
        print(f"created {target}")
    print("Only TCP loopback 127.0.0.1 configured; no public or auto interfaces")


if __name__ == "__main__":
    main()
