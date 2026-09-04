#!/usr/bin/env python3
"""Lease and probe previously committed opaque nominations.

This process receives the discovery-admin credential but neither the public
index key nor the nominator credential, so it cannot alter the immutable target
tuple that the control plane accepted earlier.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter

from discover import GlobalRateLimiter, http_json
from run_multilane import HARD_MAX_TOTAL, RUNNER_MAX_RATE, ingest


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe opaque durable nominations")
    ap.add_argument("--api-base", default=os.getenv("LEAKY_API_BASE"))
    ap.add_argument("--admin-token", default=os.getenv("LEAKY_ADMIN_TOKEN"))
    ap.add_argument("--manifest", default="nomination-manifest.json")
    ap.add_argument("--output", default="discovery-run.json")
    ap.add_argument("--rate", type=float, default=0.2)
    ap.add_argument("--ingest", action="store_true")
    args = ap.parse_args()
    if not args.api_base or not args.admin_token:
        raise SystemExit("API base and discovery-admin token are required")
    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    ids = manifest.get("nomination_ids") or []
    if not isinstance(ids, list) or not ids or len(ids) > HARD_MAX_TOTAL:
        raise SystemExit("invalid or empty nomination manifest")

    limiter = GlobalRateLimiter(min(args.rate, RUNNER_MAX_RATE))
    results = []
    skipped = Counter()
    print(f"[*] Probing up to {len(ids)} immutable nomination(s) @ {min(args.rate, RUNNER_MAX_RATE)}/s")
    for position, nomination_id in enumerate(ids, 1):
        limiter.wait()
        lease_status, lease = http_json(
            f"{args.api_base.rstrip('/')}/v1/admin/discovery/lease",
            method="POST",
            headers={"X-Admin-Token": args.admin_token},
            data={"nomination_id": nomination_id},
            timeout=20,
        )
        if lease_status != 200 or not isinstance(lease, dict):
            reason = (lease or {}).get("error", f"lease_http_{lease_status}") \
                if isinstance(lease, dict) else f"lease_http_{lease_status}"
            skipped[str(reason)] += 1
            print(f"[{position}/{len(ids)}] SKIP:{reason}")
            continue
        probe_status, probe = http_json(
            f"{args.api_base.rstrip('/')}/v1/admin/discovery/probe",
            method="POST",
            headers={"X-Admin-Token": args.admin_token},
            data={"permit_id": lease.get("permit_id")},
            timeout=30,
        )
        if probe_status != 200 or not isinstance(probe, dict):
            raise SystemExit(f"governed probe commit failed (HTTP {probe_status})")
        record = probe.get("nomination") or {}
        result = {
            **record,
            **(probe.get("result") or {}),
            "outcome": probe.get("outcome"),
        }
        results.append(result)
        print(
            f"[{position}/{len(ids)}] {record.get('stack') or '?'} "
            f"{record.get('country_code') or '?'} {probe.get('outcome') or '?'}"
        )

    exposed = [result for result in results if result.get("outcome") == "exposed"]
    meta = {
        **(manifest.get("meta") or {}),
        "leased_count": len(results),
        "skipped_count": sum(skipped.values()),
        "skipped_reasons": dict(skipped),
        "exposed_count": len(exposed),
        "rate": min(args.rate, RUNNER_MAX_RATE),
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump({"meta": meta, "results": results, "exposed": exposed}, handle, indent=2)
        handle.write("\n")
    print(
        f"[+] governed results: nominated={len(ids)} leased={len(results)} "
        f"skipped={sum(skipped.values())} exposed={len(exposed)}"
    )
    if args.ingest and (results or meta.get("indexed_observed") is not None):
        ingest(args.api_base, args.admin_token, results, meta)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
