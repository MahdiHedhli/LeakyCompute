#!/usr/bin/env python3
"""
Known-vulnerability fingerprint checks (safe, read-only).

Scaffold for baking into Worker public check + GitHub CLI later.
Today: offline/CLI against known open services we already rediscovered.

Rules:
  - No exploit payloads
  - Version banners / endpoint shape only
  - Report advisory IDs + severity + remediation

Examples:
  python3 scripts/discovery/vuln_check.py --from-results data/discovery-multilane.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from typing import Any

# Advisory catalog — expand carefully; keep citations for the post
ADVISORIES = [
    {
        "id": "CVE-2024-37032",
        "stack": "ollama",
        "title": "Ollama path traversal / model handling class (historical)",
        "severity": "high",
        "check": "ollama_unauth",
        "remediation": "Upgrade Ollama; bind 127.0.0.1; reverse-proxy auth; reject path-like model names.",
    },
    {
        "id": "RAY-OPEN-DASHBOARD",
        "stack": "ray",
        "title": "Ray dashboard / Jobs API reachable without auth (exposure class)",
        "severity": "critical",
        "check": "ray_version_open",
        "remediation": "Do not expose 8265 publicly; use Anyscale open-ports-checker patterns; network policy.",
    },
    {
        "id": "JUPYTER-NO-TOKEN",
        "stack": "jupyter_open",
        "title": "Jupyter exposed without token prompt in HTML",
        "severity": "critical",
        "check": "jupyter_open",
        "remediation": "Require token/password; never publish 8888 to 0.0.0.0.",
    },
    {
        "id": "OPENAI-COMPAT-UNAUTH",
        "stack": "openai_compat",
        "title": "OpenAI-compatible /v1/models without auth",
        "severity": "high",
        "check": "openai_models_open",
        "remediation": "API keys / network isolation; disable public bind.",
    },
]


def classify_result(r: dict) -> list[dict]:
    if not r.get("exposed"):
        return []
    stack = r.get("stack") or ""
    findings = []
    for adv in ADVISORIES:
        if adv["stack"] == "ollama" and stack == "ollama":
            findings.append({**adv, "matched": True})
        elif adv["stack"] == "ray" and stack == "ray":
            findings.append({**adv, "matched": True})
        elif adv["stack"] == "jupyter_open" and stack == "jupyter_open":
            findings.append({**adv, "matched": True})
        elif adv["stack"] in ("openai_compat", "vllm", "localai", "litellm") and stack in (
            "openai_compat_8000",
            "openai_compat_8080",
            "vllm",
            "localai",
            "litellm",
        ):
            if adv["check"] == "openai_models_open":
                findings.append({**adv, "matched": True})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-results", required=True, help="discovery-multilane.json")
    ap.add_argument("--output", default="data/vuln-findings.json")
    args = ap.parse_args()

    data = json.loads(open(args.from_results).read())
    results = data.get("exposed") or data.get("results") or []
    findings = []
    for r in results:
        if not r.get("exposed"):
            continue
        for f in classify_result(r):
            findings.append(
                {
                    "ip": r.get("ip"),
                    "port": r.get("port"),
                    "stack": r.get("stack"),
                    "country_code": r.get("country_code"),
                    "asn": r.get("asn"),
                    **{k: f[k] for k in ("id", "title", "severity", "remediation")},
                }
            )

    summary = {}
    for f in findings:
        summary[f["id"]] = summary.get(f["id"], 0) + 1

    out = {
        "summary": summary,
        "count": len(findings),
        "findings": findings,
        "note": "Scaffold only — version-precise CVE matching comes next in Worker + CLI.",
    }
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(json.dumps({"count": out["count"], "summary": summary}, indent=2))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
