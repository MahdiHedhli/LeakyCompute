#!/usr/bin/env python3
"""Extract one validated production/main Cloudflare Pages deployment SHA.

The Pages API response is operational metadata, not a log artifact. This parser
accepts only the exact shape the lab gate needs and prints only the public commit
SHA. Provider errors, preview metadata, and unexpected fields never reach logs.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_METADATA_BYTES = 128 * 1024
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class DeploymentMetadataError(ValueError):
    """Cloudflare did not return one authoritative production deployment."""


def production_commit(payload: Any) -> str:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise DeploymentMetadataError("api_unsuccessful")

    rows = payload.get("result")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise DeploymentMetadataError("deployment_missing")

    row = rows[0]
    trigger = row.get("deployment_trigger")
    stage = row.get("latest_stage")
    if not isinstance(trigger, dict) or not isinstance(stage, dict):
        raise DeploymentMetadataError("deployment_shape_invalid")
    metadata = trigger.get("metadata")
    if not isinstance(metadata, dict):
        raise DeploymentMetadataError("deployment_shape_invalid")
    if row.get("environment") != "production":
        raise DeploymentMetadataError("environment_not_production")
    if metadata.get("branch") != "main":
        raise DeploymentMetadataError("branch_not_main")
    if stage.get("status") != "success":
        raise DeploymentMetadataError("deployment_not_successful")
    if row.get("is_skipped") is not False:
        raise DeploymentMetadataError("deployment_skipped_or_ambiguous")

    commit = metadata.get("commit_hash")
    if not isinstance(commit, str) or not COMMIT_SHA.fullmatch(commit):
        raise DeploymentMetadataError("commit_invalid")
    return commit


def load_payload(path: str) -> Any:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_METADATA_BYTES + 1)
    except OSError as exc:
        raise DeploymentMetadataError("metadata_unreadable") from exc
    if len(raw) > MAX_METADATA_BYTES:
        raise DeploymentMetadataError("metadata_oversized")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentMetadataError("metadata_malformed") from exc


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: parse_pages_deployment.py RESPONSE_FILE", file=sys.stderr)
        return 2
    try:
        commit = production_commit(load_payload(argv[1]))
    except DeploymentMetadataError as exc:
        print(f"Cloudflare production deployment metadata rejected: {exc}", file=sys.stderr)
        return 2
    print(commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
