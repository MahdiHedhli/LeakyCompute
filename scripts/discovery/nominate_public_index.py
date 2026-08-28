#!/usr/bin/env python3
"""Collect passive index records and exchange them for opaque durable nominations.

This process has the public-index and nominator credentials, but never receives
the discovery-admin credential and therefore cannot lease or emit target traffic.
The output contains opaque IDs and aggregate counters only; no target address is
written to the workflow workspace or public log.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter

from run_multilane import (
    HARD_MAX_TOTAL,
    LANES,
    collect_lane,
    http_json,
    partition_by_allowed_port,
    partition_by_provenance,
    require_lane_collection_succeeded,
)


def cursor_call(api_base: str, token: str, method: str = "GET", data=None):
    return http_json(
        f"{api_base.rstrip('/')}/v1/nominator/discovery/cursors",
        method=method,
        headers={"X-Nominator-Token": token},
        data=data,
        timeout=20,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Create immutable public-index nominations")
    ap.add_argument("--api-base", default=os.getenv("LEAKY_API_BASE"))
    ap.add_argument("--nominator-token", default=os.getenv("LEAKY_NOMINATOR_TOKEN"))
    ap.add_argument("--shodan-key", default=os.getenv("SHODAN_API_KEY"))
    ap.add_argument("--lanes", default="all")
    ap.add_argument("--max-total", type=int, default=HARD_MAX_TOTAL)
    ap.add_argument("--output", default="nomination-manifest.json")
    args = ap.parse_args()
    if not args.api_base or not args.nominator_token or not args.shodan_key:
        raise SystemExit("API base, nominator token, and Shodan key are required")
    if args.max_total < 1 or args.max_total > HARD_MAX_TOTAL:
        raise SystemExit(f"--max-total must be between 1 and {HARD_MAX_TOTAL}")

    status, cursor_body = cursor_call(args.api_base, args.nominator_token)
    if status != 200 or not isinstance(cursor_body, dict):
        raise SystemExit("authoritative lane cursors unavailable; no nominations created")
    cursors = cursor_body.get("cursors") or {}

    wanted = None if args.lanes == "all" else {x.strip() for x in args.lanes.split(",")}
    lanes = [lane for lane in LANES if wanted is None or lane["id"] in wanted]
    if not lanes:
        raise SystemExit("no recognized lanes selected")

    candidates = []
    failures = []
    cursor_updates = []
    index_listed = {}
    pulled = 0
    for lane in lanes:
        try:
            start_page = int((cursors.get(lane["id"]) or {}).get("page") or 1)
            found, observed, next_page, total = collect_lane(args.shodan_key, lane, start_page)
            candidates.extend(found)
            pulled += observed
            if isinstance(total, int):
                index_listed[lane["id"]] = total
            cursor_updates.append({
                "lane": lane["id"],
                "page": next_page,
                "exhausted": next_page == 1 and start_page != 1,
                "observed": observed,
            })
        except (SystemExit, Exception):
            # Index response fragments and target details never belong in a
            # public Actions log. The lane ID is enough to diagnose safely.
            print(f"[!] passive lane failed: {lane['id']}")
            failures.append(lane["id"])
        time.sleep(1.0)
    require_lane_collection_succeeded(failures)

    by_key = {}
    for candidate in candidates:
        if candidate.get("ip"):
            by_key.setdefault(f"{candidate['ip']}:{candidate.get('port')}", candidate)
    candidates = list(by_key.values())[: args.max_total]
    candidates, bad_ports = partition_by_allowed_port(candidates, LANES)
    candidates, bad_provenance = partition_by_provenance(candidates, {})
    print(
        f"[+] passive nomination gates: eligible={len(candidates)} "
        f"port_dropped={len(bad_ports)} provenance_dropped={len(bad_provenance)}"
    )

    payload = []
    for candidate in candidates:
        provenance = candidate.get("provenance") or {}
        payload.append({
            "ip": provenance.get("ip"),
            "asn": provenance.get("asn"),
            "service": provenance.get("lane"),
            "port": provenance.get("port"),
            "source": provenance.get("index"),
            "observed_at": provenance.get("observed_at"),
            "country_code": candidate.get("country_code"),
        })
    status, response = http_json(
        f"{args.api_base.rstrip('/')}/v1/nominator/discovery/nominations",
        method="POST",
        headers={"X-Nominator-Token": args.nominator_token},
        data={"nominations": payload},
        timeout=30,
    )
    if status != 200 or not isinstance(response, dict) or response.get("ok") is not True:
        raise SystemExit(f"durable nomination failed (HTTP {status}); no target traffic authorized")
    ids = response.get("created") or []
    if len(ids) != len(payload):
        raise SystemExit("durable nomination count mismatch; no target traffic authorized")

    status, _ = cursor_call(
        args.api_base,
        args.nominator_token,
        method="POST",
        data={"cursors": cursor_updates},
    )
    if status != 200:
        raise SystemExit("lane cursor commit failed; nominations exist but probing is withheld")

    manifest = {
        "nomination_ids": ids,
        "meta": {
            "lanes": [lane["id"] for lane in lanes],
            "candidate_count": len(ids),
            "pulled_count": pulled,
            "index_listed_by_lane": index_listed,
            "index_listed_records": sum(index_listed.values()),
            "provenance_enforced": True,
            "immutable_nominations": True,
            "credential_split": True,
            "mode": "durable_public_index_nomination",
        },
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print(f"[+] durable nominations committed: {len(ids)} opaque ID(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
