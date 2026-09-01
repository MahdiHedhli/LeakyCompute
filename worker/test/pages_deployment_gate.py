#!/usr/bin/env python3
"""Behavioral tests for production-only Cloudflare Pages verification."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts", "operations"))

import parse_pages_deployment as P  # noqa: E402

SHA = "a" * 40


def deployment(**overrides):
    row = {
        "environment": "production",
        "is_skipped": False,
        "latest_stage": {"status": "success"},
        "deployment_trigger": {
            "metadata": {"branch": "main", "commit_hash": SHA},
        },
    }
    for key, value in overrides.items():
        if key == "branch":
            row["deployment_trigger"]["metadata"]["branch"] = value
        elif key == "commit_hash":
            row["deployment_trigger"]["metadata"]["commit_hash"] = value
        elif key == "status":
            row["latest_stage"]["status"] = value
        else:
            row[key] = value
    return {"success": True, "result": [row]}


assert P.production_commit(deployment()) == SHA

for payload, reason in (
    (deployment(environment="preview"), "environment_not_production"),
    (deployment(branch="dependabot/example"), "branch_not_main"),
    (deployment(status="failure"), "deployment_not_successful"),
    (deployment(is_skipped=True), "deployment_skipped_or_ambiguous"),
    (deployment(commit_hash="not-a-sha"), "commit_invalid"),
    ({"success": True, "result": [{"deployment_trigger": "wrong-shape"}]}, "deployment_shape_invalid"),
    ({"success": False, "errors": [{"message": "HOSTILE PRIVATE DETAIL"}]}, "api_unsuccessful"),
    ({"success": True, "result": []}, "deployment_missing"),
):
    try:
        P.production_commit(payload)
        raise AssertionError(f"accepted rejected deployment: {reason}")
    except P.DeploymentMetadataError as exc:
        assert str(exc) == reason, exc

with tempfile.TemporaryDirectory() as tmp:
    malformed = os.path.join(tmp, "malformed.json")
    with open(malformed, "w", encoding="utf-8") as handle:
        handle.write("not-json HOSTILE PRIVATE DETAIL")
    try:
        P.load_payload(malformed)
        raise AssertionError("malformed provider metadata was accepted")
    except P.DeploymentMetadataError as exc:
        assert str(exc) == "metadata_malformed", exc

    oversized = os.path.join(tmp, "oversized.json")
    with open(oversized, "wb") as handle:
        handle.write(b"x" * (P.MAX_METADATA_BYTES + 1))
    try:
        P.load_payload(oversized)
        raise AssertionError("oversized provider metadata was accepted")
    except P.DeploymentMetadataError as exc:
        assert str(exc) == "metadata_oversized", exc

    valid = os.path.join(tmp, "valid.json")
    with open(valid, "w", encoding="utf-8") as handle:
        json.dump(deployment(), handle)
    stdout = StringIO()
    with redirect_stdout(stdout):
        assert P.main(["parse_pages_deployment.py", valid]) == 0
    assert stdout.getvalue().strip() == SHA

    hostile = os.path.join(tmp, "hostile.json")
    with open(hostile, "w", encoding="utf-8") as handle:
        json.dump({
            "success": False,
            "errors": [{"message": "HOSTILE PRIVATE DETAIL"}],
        }, handle)
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        assert P.main(["parse_pages_deployment.py", hostile]) == 2
    assert stdout.getvalue() == ""
    assert "api_unsuccessful" in stderr.getvalue()
    assert "HOSTILE PRIVATE DETAIL" not in stderr.getvalue()

print("Pages deployment gate tests passed (production/main/success only)")
