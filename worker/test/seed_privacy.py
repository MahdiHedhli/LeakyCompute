#!/usr/bin/env python3
"""Positive controls for archive-label privacy minimization."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.build_seed import redact_identifiers  # noqa: E402


CASES = {
    "/" + "Users/alice/project/model": "[redacted-user-path]/project/model",
    "/" + "home/alice/project/model": "[redacted-user-path]/project/model",
    "C:" + r"\Users\alice\project": r"[redacted-user-path]\project",
    "model-198.51.100.44": "model-[redacted-address]",
    "owner@example.net/model": "[redacted-email]/model",
}

for source, expected in CASES.items():
    actual = redact_identifiers(source)
    assert actual == expected, (source, actual, expected)

print("seed redaction positive controls passed")
