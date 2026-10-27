#!/usr/bin/env python3
"""Offline provenance and *heuristic static* check of the official RNS 1.5.7 sdist.

Does not run, install or import untrusted code from the tarball.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import tarfile

VERSION = "1.5.7"
EXPECTED_SHA256 = "2bb48232e0a10b59b2b21b60e76592362210cdabd343d7b97a3bf1aba22dd879"


def sha256_file(filename: Path) -> str:
    checksum = hashlib.sha256()
    with filename.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def inspect_link(source: str) -> dict:
    tree = ast.parse(source, filename="RNS/Link.py")
    link = next((node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Link"), None)
    if link is None:
        raise ValueError("Link class not found in package")
    methods = {node.name: node for node in link.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    observations = {}
    for name in ("rtt_packet", "__receive", "validate_request", "start_watchdog"):
        node = methods.get(name)
        if node is None:
            observations[name] = {"present": False}
            continue
        body = ast.get_source_segment(source, node) or ""
        observations[name] = {
            "present": True,
            "first_line": node.lineno,
            "last_line": node.end_lineno,
            "uses_LRRTT": "LRRTT" in body,
            "mentions_HANDSHAKE": "HANDSHAKE" in body,
            "mentions_ACTIVE": "ACTIVE" in body,
            "mentions_link_established": "link_established" in body,
            "calls_rtt_packet": "rtt_packet(" in body,
            "calls_start_watchdog": "start_watchdog(" in body,
        }
    return observations


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("archive", type=Path, help="official rns-1.5.7.tar.gz source distribution")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    digest = sha256_file(args.archive)
    report = {
        "version_target": VERSION,
        "artifact": str(args.archive),
        "sha256_observed": digest,
        "sha256_expected_pypi": EXPECTED_SHA256,
        "hash_verified": digest == EXPECTED_SHA256,
        "notes": "Static AST heuristics only, not a vulnerability finding or execution result",
    }
    if not report["hash_verified"]:
        print(json.dumps(report, indent=2))
        raise SystemExit("SHA-256 mismatch: aborting source inspection")
    with tarfile.open(args.archive, "r:gz") as tar:
        matches = [m for m in tar.getmembers() if m.isfile() and m.name.endswith("/RNS/Link.py")]
        if len(matches) != 1:
            raise SystemExit(f"Expected one Link.py in sdist, found {len(matches)}")
        selected = matches[0]
        if selected.size > 512 * 1024:
            raise SystemExit("Unexpectedly large Link.py")
        handle = tar.extractfile(selected)
        if handle is None:
            raise SystemExit("Link.py cannot be read")
        report["link_py_path"] = selected.name
        report["link_py_sha256"] = hashlib.sha256(handle.read()).hexdigest()
        handle = tar.extractfile(selected)
        assert handle is not None
        source = handle.read().decode("utf-8")
        report["routines"] = inspect_link(source)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
