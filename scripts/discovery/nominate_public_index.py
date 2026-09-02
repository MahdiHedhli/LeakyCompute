#!/usr/bin/env python3
"""Collect passive index records and exchange them for opaque durable nominations.

This process has the public-index and nominator credentials, but never receives
the discovery-admin credential and therefore cannot lease or emit target traffic.
The output contains opaque IDs and aggregate counters only; no target address is
written to the workflow workspace or public log.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone

from provenance import normalize_asn, parse_ts

from run_multilane import (
    HARD_MAX_TOTAL,
    LANES,
    PAGES_PER_RUN,
    ShodanRequestError,
    collect_lane,
    http_json,
    partition_by_allowed_port,
    partition_by_provenance,
)


# The Durable Object deliberately bounds one transaction. A governed run may
# contain several such transactions, but no request may widen this boundary.
NOMINATION_BATCH_MAX = 128


def enabled_env(name: str) -> bool:
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


class SourceBudgetConsumer:
    """Consume one strongly accounted source unit before a Shodan request."""

    def __init__(self, api_base: str, token: str):
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.consumed = 0

    def consume(self) -> None:
        status, response = http_json(
            f"{self.api_base}/v1/nominator/discovery/source-budget/consume",
            method="POST",
            headers={"X-Nominator-Token": self.token},
            data={"units": 1},
            timeout=20,
        )
        if status != 200 or not isinstance(response, dict) or response.get("ok") is not True:
            reason = response.get("error") if isinstance(response, dict) else "unavailable"
            raise SystemExit(f"source budget refused provider request: {reason}")
        self.consumed += 1


def collect_lane_with_failover(
    primary_key: str,
    secondary_key: str | None,
    secondary_enabled: bool,
    active_slot: str,
    lane: dict,
    start_page: int,
    *,
    pages_per_run: int,
    budget_consumer,
):
    """Collect one lane, promoting the secondary only for invalid primary auth."""
    active_key = secondary_key if active_slot == "secondary" else primary_key
    try:
        return (
            collect_lane(
                active_key,
                lane,
                start_page,
                pages_per_run=pages_per_run,
                budget_consumer=budget_consumer,
            ),
            active_slot,
        )
    except ShodanRequestError as error:
        if (
            error.category != "authentication_rejected" or
            active_slot != "primary" or
            not secondary_enabled or
            not secondary_key
        ):
            raise
        print("[!] primary Shodan credential unavailable; promoting configured secondary for this run")
        return (
            collect_lane(
                secondary_key,
                lane,
                start_page,
                pages_per_run=pages_per_run,
                budget_consumer=budget_consumer,
            ),
            "secondary",
        )


def cursor_call(api_base: str, token: str, method: str = "GET", data=None):
    return http_json(
        f"{api_base.rstrip('/')}/v1/nominator/discovery/cursors",
        method=method,
        headers={"X-Nominator-Token": token},
        data=data,
        timeout=20,
    )


def require_nomination_lane_available(completed: set[str], failures: list[str]) -> None:
    """Isolate failed passive lanes while requiring at least one healthy lane.

    A failed lane contributes no candidates, advances no cursor, and cannot
    publish a partial global index measurement. Healthy lanes retain their own
    fresh provenance and may continue through the normal nomination gates.
    """
    if not completed:
        raise SystemExit("no passive lane succeeded; no nominations created")
    if failures:
        print(
            "[!] isolated passive lane failure(s): "
            + ", ".join(sorted(failures))
            + "; continuing with healthy lanes only"
        )


def partition_by_durable_authority(candidates: list[dict]) -> tuple[list[dict], list[dict]]:
    """Mirror the stronger nomination-ledger checks before committing a batch."""
    accepted = []
    dropped = []
    now = datetime.now(timezone.utc)
    for candidate in candidates:
        provenance = candidate.get("provenance") or {}
        reason = None
        try:
            candidate_ip = ipaddress.ip_address(str(candidate.get("ip")))
            provenance_ip = ipaddress.ip_address(str(provenance.get("ip")))
        except ValueError:
            reason = "durable_address_missing"
        else:
            if candidate_ip != provenance_ip:
                reason = "durable_address_mismatch"
        if reason is None and (
            str(provenance.get("lane") or "").strip().lower()
            != str(candidate.get("stack") or "").strip().lower()
        ):
            reason = "durable_lane_mismatch"
        if reason is None and normalize_asn(provenance.get("asn")) is None:
            reason = "durable_asn_missing"
        observed = parse_ts(provenance.get("observed_at"))
        if reason is None and (observed is None or observed > now):
            reason = "durable_time_invalid"
        if reason:
            dropped.append({**candidate, "dropped_by": reason})
        else:
            accepted.append(candidate)
    return accepted, dropped


def commit_nomination_batches(api_base: str, token: str, payload: list[dict]) -> tuple[list[str], int]:
    """Commit a run envelope through bounded authoritative transactions.

    Candidate-level rejections stay isolated: the control plane has already
    refused them, so withholding valid opaque IDs would reduce availability
    without improving safety. Malformed responses and an all-rejected envelope
    still fail closed before target traffic.
    """
    ids: list[str] = []
    rejected_total = 0
    for offset in range(0, len(payload), NOMINATION_BATCH_MAX):
        batch = payload[offset : offset + NOMINATION_BATCH_MAX]
        status, response = http_json(
            f"{api_base.rstrip('/')}/v1/nominator/discovery/nominations",
            method="POST",
            headers={"X-Nominator-Token": token},
            data={"nominations": batch},
            timeout=30,
        )
        if status != 200 or not isinstance(response, dict):
            raise SystemExit(f"durable nomination failed (HTTP {status}); no target traffic authorized")
        created = response.get("created")
        rejected = response.get("rejected")
        if not isinstance(created, list) or not isinstance(rejected, list):
            raise SystemExit("invalid durable nomination response; no target traffic authorized")
        if len(created) + len(rejected) != len(batch):
            raise SystemExit("durable nomination count mismatch; no target traffic authorized")
        if not all(isinstance(value, str) and value for value in created):
            raise SystemExit("invalid durable nomination identifiers; no target traffic authorized")
        if not all(
            isinstance(row, dict) and row.get("error") == "invalid_public_index_nomination"
            for row in rejected
        ):
            raise SystemExit("unexpected durable nomination rejection; no target traffic authorized")
        ids.extend(created)
        rejected_total += len(rejected)
    if not ids:
        raise SystemExit("all durable nominations were rejected; no target traffic authorized")
    return ids, rejected_total


def main() -> int:
    ap = argparse.ArgumentParser(description="Create immutable public-index nominations")
    ap.add_argument("--api-base", default=os.getenv("LEAKY_API_BASE"))
    ap.add_argument("--nominator-token", default=os.getenv("LEAKY_NOMINATOR_TOKEN"))
    ap.add_argument(
        "--shodan-key",
        default=os.getenv("SHODAN_API_KEY_PRIMARY") or os.getenv("SHODAN_API_KEY"),
    )
    ap.add_argument("--secondary-shodan-key", default=os.getenv("SHODAN_API_KEY_SECONDARY"))
    ap.add_argument(
        "--allow-secondary-failover",
        action="store_true",
        default=enabled_env("SHODAN_SECONDARY_FAILOVER_ENABLED"),
    )
    ap.add_argument("--pages-per-lane", type=int, default=PAGES_PER_RUN)
    ap.add_argument("--lanes", default="all")
    ap.add_argument("--max-total", type=int, default=HARD_MAX_TOTAL)
    ap.add_argument("--output", default="nomination-manifest.json")
    args = ap.parse_args()
    if not args.api_base or not args.nominator_token or not args.shodan_key:
        raise SystemExit("API base, nominator token, and Shodan key are required")
    if args.max_total < 1 or args.max_total > HARD_MAX_TOTAL:
        raise SystemExit(f"--max-total must be between 1 and {HARD_MAX_TOTAL}")
    if args.pages_per_lane != 1:
        raise SystemExit("scheduled nomination requires exactly one incremental page per search lane")
    if args.allow_secondary_failover and not args.secondary_shodan_key:
        raise SystemExit("secondary failover enabled without a configured secondary credential")

    status, cursor_body = cursor_call(args.api_base, args.nominator_token)
    if status != 200 or not isinstance(cursor_body, dict):
        raise SystemExit("authoritative lane cursors unavailable; no nominations created")
    cursors = cursor_body.get("cursors") or {}

    wanted = None if args.lanes == "all" else {x.strip() for x in args.lanes.split(",")}
    lanes = [lane for lane in LANES if wanted is None or lane["id"] in wanted]
    if not lanes:
        raise SystemExit("no recognized lanes selected")
    # Search lanes need one source unit; ASN lanes need a facet plus the
    # rotating group calls. Spend scarce paced headroom on complete small units
    # before beginning a larger lane that might stop midway.
    lanes.sort(key=lambda lane: lane.get("mode") == "asn")

    candidates = []
    failures = []
    completed = set()
    cursor_updates = []
    index_listed = {}
    pulled = 0
    source_budget = SourceBudgetConsumer(args.api_base, args.nominator_token)
    active_key_slot = "primary"
    for lane in lanes:
        try:
            start_page = int((cursors.get(lane["id"]) or {}).get("page") or 1)
            lane_result, active_key_slot = collect_lane_with_failover(
                args.shodan_key,
                args.secondary_shodan_key,
                args.allow_secondary_failover,
                active_key_slot,
                lane,
                start_page,
                pages_per_run=args.pages_per_lane,
                budget_consumer=source_budget.consume,
            )
            found, observed, next_page, total = lane_result
            candidates.extend(found)
            pulled += observed
            if isinstance(total, int):
                index_listed[lane["id"]] = total
            completed.add(lane["id"])
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
    require_nomination_lane_available(completed, failures)

    by_key = {}
    for candidate in candidates:
        if candidate.get("ip"):
            by_key.setdefault(f"{candidate['ip']}:{candidate.get('port')}", candidate)
    candidates = list(by_key.values())
    candidates, bad_ports = partition_by_allowed_port(candidates, LANES)
    candidates, bad_provenance = partition_by_provenance(candidates, {})
    candidates, bad_authority = partition_by_durable_authority(candidates)
    candidates = candidates[: args.max_total]
    print(
        f"[+] passive nomination gates: eligible={len(candidates)} "
        f"port_dropped={len(bad_ports)} provenance_dropped={len(bad_provenance)} "
        f"authority_dropped={len(bad_authority)}"
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
    ids, authoritative_rejections = commit_nomination_batches(
        args.api_base, args.nominator_token, payload
    )
    if authoritative_rejections:
        print(
            f"[!] durable nomination candidate rejections: {authoritative_rejections}; "
            "continuing with authoritatively accepted opaque IDs only"
        )

    status, _ = cursor_call(
        args.api_base,
        args.nominator_token,
        method="POST",
        data={"cursors": cursor_updates},
    )
    if status != 200:
        raise SystemExit("lane cursor commit failed; nominations exist but probing is withheld")

    requested_lane_ids = [lane["id"] for lane in lanes]
    completed_lane_ids = [lane_id for lane_id in requested_lane_ids if lane_id in completed]
    manifest = {
        "nomination_ids": ids,
        "meta": {
            "lanes": completed_lane_ids,
            "requested_lanes": requested_lane_ids,
            "failed_lanes": sorted(failures),
            "partial_lane_run": bool(failures),
            "candidate_count": len(ids),
            "requested_candidate_count": len(payload),
            "authoritative_rejections": authoritative_rejections,
            "nomination_batches": (len(payload) + NOMINATION_BATCH_MAX - 1) // NOMINATION_BATCH_MAX,
            "nomination_batch_max": NOMINATION_BATCH_MAX,
            "pulled_count": pulled,
            "index_listed_by_lane": index_listed,
            "index_listed_records": sum(index_listed.values()),
            "indexed_observed_publication": (
                "withheld_incomplete_lane_measurement"
                if failures else "candidate_feed_only"
            ),
            "provenance_enforced": True,
            "immutable_nominations": True,
            "credential_split": True,
            "source_budget_enforced": True,
            "source_units_consumed": source_budget.consumed,
            "source_key_slot": active_key_slot,
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
