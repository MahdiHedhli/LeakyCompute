#!/usr/bin/env python3
"""
Multi-lane discovery runner for a solid pre-post seed.

Lanes = high-signal Shodan fingerprints (Ollama, Jupyter-unauth, Ray, Open WebUI, …).
Each lane: passive pull (limited) → stack-aware safe GET → ingest with geo.

Four gates stand between a candidate and a packet, all of them ahead of the
dry-run branch so the written plan is the plan:

  I-22  provenance — public index record, or approved operator request
  I-25  exclusions — fail closed; --ingest refuses to run without the list
  I-24  interval   — one probe cycle per host per 14 days, fail closed. The
                     clock is the probe *attempt* ledger, not the hit store:
                     the hit store holds only hosts that answered, so a host
                     that has since been firewalled left no trace there and was
                     re-probed on every run.
  I-24  rate       — global ceiling, per-/24 and per-ASN ceilings

Usage:
  export SHODAN_API_KEY=...
  export LEAKY_API_BASE=https://leakycompute-api.mhedhli.workers.dev
  export LEAKY_ADMIN_TOKEN=...

  python3 scripts/discovery/run_multilane.py --dry-run
  python3 scripts/discovery/run_multilane.py --ingest --rate 0.2

  # governance smoke test — no Shodan key, no admin API, no packets
  python3 scripts/discovery/run_multilane.py --self-test --output /tmp/plan.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any

# Reuse helpers from discover.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from discover import (  # noqa: E402
    HARD_MAX_RATE,
    PROBE_USER_AGENT,
    GlobalRateLimiter,
    hosts_for_asn,
    http_json,
    parse_asn_facets,
    shodan_search,
)
from exclusions import (  # noqa: E402
    ExclusionsUnavailable,
    fetch_exclusions,
    filter_candidates,
)
from provenance import (  # noqa: E402
    ProvenanceUnavailable,
    candidates_for_requests,
    index_provenance,
    load_approved_requests,
    parse_ts,
    partition_by_provenance,
    provenance_from_corpus_source,
)

# I-23: the agent an operator will actually see, and the one /scanning tells
# them to look for. It was previously a constant nothing referenced, so probes
# went out under discover.py's "LeakyCompute-Discovery/1.0" while the public
# page named a third string — and a page that disagrees with the packet is
# exactly what I-23's "one search" promise cannot survive.
USER_AGENT = PROBE_USER_AGENT

# --- I-24: probe rate is bounded per target, not per run --------------------
# Re-verification is a background process. These bounds are what stops a raised
# corpus (spec 001 step 4) from turning into a burst that looks, from the far
# end, exactly like the sweeps this project exists to be distinguishable from.

REPROBE_INTERVAL_DAYS = 14  # at most one probe cycle per host per 14 days

# Ceiling below discover.py's HARD_MAX_RATE. HARD_MAX_RATE is the absolute floor
# of sanity for any probing this repo does; bulk re-verification is held slower
# than that on purpose, because it is unattended and long-running.
RUNNER_MAX_RATE = 0.5

# One in-flight probe per neighbourhood, and a gap before the next. Concurrency
# alone is a weak bound at one worker — the spacing is what a /24's owner would
# actually notice the absence of in their logs.
MAX_INFLIGHT_PER_24 = 1
MIN_SECONDS_BETWEEN_SAME_24 = 30.0
MAX_INFLIGHT_PER_ASN = 2
MIN_SECONDS_BETWEEN_SAME_ASN = 5.0

# IPv6 has no /24; /48 is the closest thing to "one operator's neighbourhood".
V6_BUCKET_PREFIX = 48


class IntervalDataUnavailable(RuntimeError):
    """Raised when last-seen data cannot be read. Callers must not probe (I-24)."""


def bucket_keys(cand: dict) -> tuple[str | None, str | None]:
    """(neighbourhood, asn) keys used for the per-bucket ceilings."""
    try:
        ip = ipaddress.ip_address(str(cand.get("ip")))
    except ValueError:
        return None, None
    prefix = 24 if ip.version == 4 else V6_BUCKET_PREFIX
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    asn = str(cand.get("asn") or "").upper() or None
    return str(net), asn


class BucketGate:
    """
    Per-bucket in-flight ceiling plus minimum spacing between entries.

    Threads always take the neighbourhood gate before the ASN gate, and a thread
    holding an ASN slot never waits on a neighbourhood slot, so the wait graph
    stays acyclic.
    """

    def __init__(self, max_inflight: int, min_interval: float):
        self._max = max(1, int(max_inflight))
        self._min_interval = float(min_interval)
        self._cv = threading.Condition()
        self._inflight: dict[str, int] = {}
        self._next_ok: dict[str, float] = {}

    def acquire(self, key: str | None) -> None:
        if key is None:
            return
        with self._cv:
            while True:
                now = time.monotonic()
                ready = now >= self._next_ok.get(key, 0.0)
                if ready and self._inflight.get(key, 0) < self._max:
                    self._inflight[key] = self._inflight.get(key, 0) + 1
                    self._next_ok[key] = now + self._min_interval
                    return
                wait = self._next_ok.get(key, 0.0) - now if not ready else 1.0
                self._cv.wait(timeout=max(0.05, min(wait, 5.0)))

    def release(self, key: str | None) -> None:
        if key is None:
            return
        with self._cv:
            left = self._inflight.get(key, 1) - 1
            if left > 0:
                self._inflight[key] = left
            else:
                self._inflight.pop(key, None)
            self._cv.notify_all()


def spread_by_bucket(cands: list[dict]) -> list[dict]:
    """
    Round-robin candidates across neighbourhoods.

    Purely an ordering change: the ceilings above are the enforcement. Feeding
    them a list already sorted by ASN would make every acquire() a stall, and a
    run that spends its life blocked is a run someone will be tempted to widen.
    """
    order: list[str] = []
    buckets: dict[str, list[dict]] = {}
    for c in cands:
        k = bucket_keys(c)[0] or "?"
        if k not in buckets:
            buckets[k] = []
            order.append(k)
        buckets[k].append(c)
    out: list[dict] = []
    while len(out) < len(cands):
        for k in order:
            if buckets[k]:
                out.append(buckets[k].pop(0))
    return out


def fetch_hits(api_base: str, token: str, limit: int = 500) -> list[dict]:
    """
    Read the admin hit store: the corpus, and the last-seen clock behind I-24.

    Raises rather than returning [] on failure — discover.py's fetch_prior_hits
    logs and returns empty, which is fine when the store is only a source of
    extra candidates but wrong once it is also the record of what we probed
    last week. An empty map is indistinguishable from "nothing has ever been
    probed", so a fetch error would re-probe the whole corpus at once: the exact
    burst I-24 exists to prevent.
    """
    if not api_base or not token:
        raise IntervalDataUnavailable(
            "api_base and admin token are required to read last-seen data"
        )
    status, data = http_json(
        f"{api_base.rstrip('/')}/v1/admin/discovery/hits?limit={limit}",
        headers={"X-Admin-Token": token},
    )
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("hits"), list):
        raise IntervalDataUnavailable(f"could not read hit store: HTTP {status} {data}")
    return [h for h in data["hits"] if isinstance(h, dict) and h.get("ip")]


def fetch_probe_clock(api_base: str, token: str) -> dict[str, str]:
    """
    The I-24 re-probe clock: when we last *sent* each host a request.

    fetch_hits() alone is not this clock, in two ways that both fail open:

      - it only ever contains hosts that ANSWERED. A host that has since been
        firewalled leaves no record, so it looked like one we had never touched
        and was re-probed on every run — daily, forever, aimed at the operators
        who had already closed the port and had the least reason to tolerate us.
      - it is one page of the corpus, ordered by insertion. Past ~500 hosts —
        which is the point of spec 001 step 4 — a host first seen months ago
        falls outside the window and reads as never-probed even though it is in
        the corpus.

    This endpoint returns the whole ledger in one read, attempts included. Same
    fail-closed contract as fetch_hits: an unreadable clock raises, because an
    empty map is indistinguishable from "nothing has ever been probed".
    """
    if not api_base or not token:
        raise IntervalDataUnavailable(
            "api_base and admin token are required to read the probe clock"
        )
    status, data = http_json(
        f"{api_base.rstrip('/')}/v1/admin/discovery/clock",
        headers={"X-Admin-Token": token},
    )
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("attempts"), dict):
        raise IntervalDataUnavailable(f"could not read probe clock: HTTP {status} {data}")
    return {str(k): v for k, v in data["attempts"].items() if k}


def last_seen_map(hits: list[dict], attempts: dict[str, str] | None = None) -> dict[str, str]:
    """
    Merge the two clocks, newest wins.

    An attempt and a success are both contact for I-24's purposes: the interval
    bounds what we send, not what we learn.
    """
    merged: dict[str, str] = dict(attempts or {})
    for h in hits:
        ip = str(h["ip"])
        seen = h.get("last_seen")
        prev = merged.get(ip)
        if seen and (not prev or str(seen) > str(prev)):
            merged[ip] = seen
        elif ip not in merged:
            merged[ip] = seen
    return merged


def filter_by_interval(
    cands: list[dict], last_seen: dict[str, str], interval_days: int
) -> tuple[list[dict], list[dict]]:
    """Split into (due, too_soon) on the I-24 re-probe interval."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=interval_days)
    due, too_soon = [], []
    for c in cands:
        seen = parse_ts(last_seen.get(str(c.get("ip"))))
        # An unparseable timestamp on a host we have a record for is not a
        # licence to probe it now; treat it as recent.
        if seen is None and str(c.get("ip")) in last_seen:
            too_soon.append({**c, "skipped_by": "last_seen_unparseable"})
        elif seen is not None and seen > cutoff:
            too_soon.append({**c, "skipped_by": f"probed_{seen.date().isoformat()}"})
        else:
            due.append(c)
    return due, too_soon

# --- Lane table -------------------------------------------------------------
#
# Three keys carry the safety argument. They are not interchangeable.
#
# `search_limit` / `top_asns` × `hosts_per_asn` — PASSIVE. How much of a public
#   index we read. No packet reaches a third party, so the only bounds that
#   apply are the source's terms of service and our API quota (I-21). Spec 001
#   §3 unties this from the probe budget: while the two were equal, the number
#   we could honestly publish was set by the number of hosts we were willing to
#   touch, which is a claim about our restraint, not about the internet.
#
# `max_hosts` — ACTIVE. How many hosts of that lane enter read-only
#   re-verification. Held at its pre-decoupling value on purpose: raising
#   passive reading is free, raising probe volume is not (I-18). The run-level
#   `--max-total`, the 14-day per-host interval, the per-/24 and per-ASN
#   ceilings and RUNNER_MAX_RATE (I-24) all still bind underneath it.
#
# `query` — every lane pins an explicit `port:` filter. match_to_candidate()
#   takes the probe port from the index record rather than from `port_default`,
#   so an unpinned query is the route by which an arbitrary port becomes a
#   probe target. Pinning is how I-5's per-service allowlist survives the trip
#   off-Worker, where resolvePort() cannot enforce it.
#
# `probe_path` — metadata, health, version or listing only (I-2). A path that
#   makes the target *do* something does not go in this table whatever it would
#   tell us. Yield is not a reason; there is no reason.
#
# Costing a full run: ~18 search pages plus ~27 per-ASN queries. If the account
# quota is the entry membership tier, rotate lanes with --lanes rather than
# raising these further — an over-quota lane fails to a zero, and a zero here
# reads as "no exposure" instead of "no credits".
LANES: list[dict[str, Any]] = [
    {
        "id": "ollama",
        "query": "product:Ollama port:11434",
        "port_default": 11434,
        "probe_path": "/api/ps",
        "mode": "asn",  # top ASNs
        "top_asns": 15,
        "hosts_per_asn": 15,
        "max_hosts": 48,
    },
    {
        "id": "jupyter",
        "query": 'http.title:"Jupyter" port:8888 -http.html:"token"',
        "port_default": 8888,
        "probe_path": "/",
        "mode": "search",
        "search_limit": 200,
        "max_hosts": 40,
    },
    {
        "id": "ray",
        "query": "port:8265",
        "port_default": 8265,
        "probe_path": "/api/version",
        "mode": "search",
        "search_limit": 200,
        "max_hosts": 40,
    },
    {
        "id": "open_webui",
        "query": 'http.title:"Open WebUI" port:8080',
        "port_default": 8080,
        # Public config document. Preferred over "/" because the SPA shell at
        # "/" renders for an instance that is fully locked down, so a 200 there
        # is weak evidence for the only claim we make (I-3): that the endpoint
        # answered an unauthenticated read.
        "probe_path": "/api/config",
        "mode": "asn",
        "top_asns": 12,
        "hosts_per_asn": 12,
        "max_hosts": 40,
    },
    {
        "id": "localai",
        "query": 'http.html:"LocalAI" port:8080',
        "port_default": 8080,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 150,
        "max_hosts": 30,
    },
    {
        "id": "litellm",
        "query": 'http.html:"LiteLLM" port:4000',
        "port_default": 4000,
        # NOT /health. On a LiteLLM proxy that path is not metadata: it runs a
        # live check by issuing a real completion against every model in the
        # operator's config, so probing it would make the target do work and
        # bill the operator for it — on exactly the unauthenticated proxies this
        # lane exists to find. That is what I-2 forbids and what I-3 forbids
        # demonstrating. /health/liveliness is the static equivalent: it returns
        # a constant and calls no model.
        "probe_path": "/health/liveliness",
        "mode": "search",
        "search_limit": 150,
        "max_hosts": 30,
    },
    {
        "id": "vllm",
        "query": 'http.html:"vLLM" port:8000',
        "port_default": 8000,
        # /version is deliberately NOT used. vLLM's API-key middleware only
        # guards /v1/*, so /version answers even on a key-protected server: a
        # 200 there would evidence reachability, not unauthenticated read, and
        # we would be publishing the wrong claim (I-3). /v1/models is behind
        # the same gate a real caller hits, and is a listing endpoint (I-2).
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 200,
        "max_hosts": 30,
    },
    {
        "id": "openai_compat_8000",
        "query": 'port:8000 http.html:"/v1/models"',
        "port_default": 8000,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 150,
        "max_hosts": 25,
    },
    {
        "id": "openai_compat_8080",
        "query": 'port:8080 http.html:"/v1/models"',
        "port_default": 8080,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 150,
        "max_hosts": 25,
    },
    {
        "id": "comfyui",
        "query": 'port:8188 http.title:"ComfyUI"',
        "port_default": 8188,
        "probe_path": "/system_stats",
        "mode": "search",
        "search_limit": 150,
        "max_hosts": 35,
    },
    {
        "id": "gradio",
        "query": 'http.title:"Gradio" port:7860',
        "port_default": 7860,
        # The interface schema. It is the read that stops short of the one
        # thing a Gradio host must never receive from us: /config describes the
        # endpoints, /run/* and /queue/join would invoke them (I-2, I-3).
        "probe_path": "/config",
        "mode": "search",
        "search_limit": 150,
        "max_hosts": 25,
    },
    {
        "id": "mlflow",
        "query": 'http.title:"MLflow" port:5000',
        "port_default": 5000,
        # Health rather than the tracking API: experiment and run listings are
        # content we would then have to refuse to retain under I-26.
        "probe_path": "/health",
        "mode": "search",
        "search_limit": 100,
        "max_hosts": 25,
    },
    {
        "id": "triton",
        # Triton's metrics port 8002 is left out of the table entirely. It is a
        # legitimate read, but the Prometheus exposition is unbounded and the
        # runner's http_json() has no equivalent of the Worker's 32 KB cap
        # (I-7), so a hostile target could stream at it.
        "query": 'port:8000 "Triton Inference Server"',
        "port_default": 8000,
        # Server metadata (name, version, extensions) under the KServe v2
        # protocol. The model inventory is NOT probed: v2 exposes it as
        # POST /v2/repository/index, and no finding is worth a non-GET (I-1).
        "probe_path": "/v2",
        "mode": "search",
        "search_limit": 100,
        "max_hosts": 20,
    },
    {
        "id": "tensorboard",
        "query": 'http.title:"TensorBoard" port:6006',
        "port_default": 6006,
        # Enabled-plugin listing. Chosen over /data/logdir, which returns a
        # host filesystem path — more than the finding needs, and retained
        # nowhere under I-26.
        "probe_path": "/data/plugins_listing",
        "mode": "search",
        "search_limit": 100,
        "max_hosts": 20,
    },
]


def extract_geo(match: dict) -> dict:
    loc = match.get("location") or {}
    asn = match.get("asn") or ""
    if isinstance(asn, int):
        asn = f"AS{asn}"
    elif asn and not str(asn).upper().startswith("AS"):
        asn = f"AS{asn}"
    return {
        "country": loc.get("country_name"),
        "country_code": loc.get("country_code"),
        "city": loc.get("city"),
        "asn": str(asn).upper() if asn else None,
        "org": match.get("org") or match.get("isp"),
        "product": match.get("product"),
        "lat": loc.get("latitude"),
        "lon": loc.get("longitude"),
    }


def match_to_candidate(m: dict, lane: dict) -> dict:
    geo = extract_geo(m)
    return {
        "ip": m.get("ip_str") or m.get("ip"),
        "port": int(m.get("port") or lane["port_default"]),
        "stack": lane["id"],
        "probe_path": lane["probe_path"],
        "source": f"shodan:{lane['id']}",
        # I-22(a): the index listing is the entitlement to probe, so it travels
        # with the candidate instead of being inferred from which lane ran.
        "provenance": index_provenance("shodan", lane["query"], lane["id"], "lane_search"),
        **geo,
    }


def collect_lane(api_key: str, lane: dict) -> tuple[list[dict], int]:
    """
    Returns (candidates, indexed_observed).

    The second number is spec §4's middle column: unique hosts this lane's
    public-index query listed, before `max_hosts` cut the set down to what we
    are willing to probe. It is counted, never probed (I-21), and it is reported
    on its own line so a larger passive reading can never be read as a larger
    number of hosts we touched. Without it /v1/stats published a hard zero
    beside the 19,348 archive figure — a new shape of the same misleading
    juxtaposition spec 001 was written to correct.
    """
    print(f"\n=== LANE {lane['id']} · {lane['query']!r} ===")
    cands: list[dict] = []
    if lane["mode"] == "asn":
        # facet + top ASNs
        sample, facets = shodan_search(
            api_key, lane["query"], limit=5, facets="asn:20,org:15"
        )
        asns = parse_asn_facets(facets)
        print(f"  total indexed (sample page) facets ASNs={len(asns)}")
        for row in asns[: lane.get("top_asns", 10)]:
            asn = row["asn"]
            try:
                hosts = hosts_for_asn(
                    api_key, lane["query"], asn, lane.get("hosts_per_asn", 6)
                )
            except SystemExit as e:
                print(f"  ! {asn}: {e}")
                hosts = []
            print(f"  {asn}: {len(hosts)} hosts")
            for h in hosts:
                # hosts_for_asn returns simplified dicts without full location
                # re-fetch is expensive; use what we have + later geo from search matches when present
                c = {
                    "ip": h["ip"],
                    "port": int(h.get("port") or lane["port_default"]),
                    "stack": lane["id"],
                    "probe_path": lane["probe_path"],
                    "source": h.get("source") or f"shodan_asn:{asn}",
                    "provenance": index_provenance(
                        "shodan", f"{lane['query']} asn:{asn}", lane["id"], "lane_asn_facet"
                    ),
                    "asn": asn,
                    "org": h.get("org"),
                    "product": h.get("product"),
                    "country": h.get("country"),
                    "country_code": h.get("country_code"),
                    "city": h.get("city"),
                }
                cands.append(c)
            time.sleep(1.0)
        # also add sample matches which have full geo
        for m in sample:
            cands.append(match_to_candidate(m, lane))
    else:
        matches, facets = shodan_search(
            api_key,
            lane["query"],
            limit=lane.get("search_limit", 30),
            facets="asn:15,country:20",
        )
        print(f"  matches={len(matches)} countries_facet={len((facets or {}).get('country') or [])}")
        for m in matches:
            cands.append(match_to_candidate(m, lane))

    # dedupe by ip:port
    by_key: dict[str, dict] = {}
    for c in cands:
        if not c.get("ip"):
            continue
        k = f"{c['ip']}:{c['port']}"
        prev = by_key.get(k)
        if not prev:
            by_key[k] = c
        else:
            for field in ("country", "country_code", "city", "asn", "org", "product"):
                if c.get(field) and not prev.get(field):
                    prev[field] = c[field]
    observed = len(by_key)
    out = list(by_key.values())[: lane.get("max_hosts", 40)]
    print(f"  unique candidates this lane: {len(out)} (indexed, observed: {observed})")
    return out, observed


VERSION_KEYS = ("version", "server_version", "ray_version", "app_version")


def version_from_payload(payload: Any) -> str | None:
    """
    Version string out of a metadata response, when the endpoint volunteered one.

    Retained under I-26 and the only input to the tier-2 OSV lookup. Nothing is
    requested in order to obtain it — this reads what the probe already came
    back with.
    """
    if not isinstance(payload, dict):
        return None
    for key in VERSION_KEYS:
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:64]
    return None


def safe_probe(ip: str, port: int, path: str, timeout: float, limiter: GlobalRateLimiter) -> dict:
    limiter.wait()
    url = f"http://{ip}:{port}{path}"
    # I-23: attributable, and identical to what /scanning tells operators to
    # search for. I-6 (no redirects) is enforced inside http_json.
    status, payload = http_json(
        url, timeout=timeout, headers={"User-Agent": USER_AGENT}
    )
    exposed = False
    models: list[dict] = []
    detail = None

    if status == 200:
        # Heuristics by path
        if path in ("/api/ps", "/api/tags") and isinstance(payload, dict):
            exposed = True
            raw = payload.get("models") or []
            models = [
                {"name": m.get("name") or m.get("model"), "size": m.get("size")}
                for m in raw[:25]
                if isinstance(m, dict)
            ]
        elif path == "/v1/models" and isinstance(payload, dict):
            data = payload.get("data") or payload.get("models") or []
            if isinstance(data, list) and (data or "object" in payload.get("object", "")):
                exposed = True
                models = [
                    {"name": m.get("id") or m.get("name"), "size": None}
                    for m in data[:25]
                    if isinstance(m, dict)
                ]
            elif "data" in payload or "object" in payload:
                exposed = True
        elif path in ("/api/version", "/health", "/health/liveliness", "/system_stats", "/v2"):
            # any 200 JSON/text is a live open service for our purposes
            exposed = True
            if isinstance(payload, dict):
                detail = {k: payload.get(k) for k in list(payload)[:8]}
        elif path == "/":
            # unauth landing page — treat 200 as open UI
            exposed = True
            if isinstance(payload, str) and len(payload) > 0:
                detail = {"html_len": len(payload)}
        else:
            exposed = True

    return {
        "status": status,
        "exposed": exposed,
        "models": models,
        "detail": detail,
        "version": version_from_payload(payload) if exposed else None,
        "error": None if status else payload,
    }


def run_probes(cands: list[dict], rate: float, workers: int, timeout: float) -> list[dict]:
    # I-24 global ceiling: the runner's own limit first, then the repo-wide
    # absolute one from discover.py. Neither can be raised by a flag.
    limiter = GlobalRateLimiter(min(rate, RUNNER_MAX_RATE, HARD_MAX_RATE))
    workers = max(1, min(workers, 2))
    net_gate = BucketGate(MAX_INFLIGHT_PER_24, MIN_SECONDS_BETWEEN_SAME_24)
    asn_gate = BucketGate(MAX_INFLIGHT_PER_ASN, MIN_SECONDS_BETWEEN_SAME_ASN)
    results: list[dict] = []

    def one(c: dict):
        net_key, asn_key = bucket_keys(c)
        net_gate.acquire(net_key)
        try:
            asn_gate.acquire(asn_key)
            try:
                pr = safe_probe(
                    c["ip"],
                    int(c["port"]),
                    c.get("probe_path") or "/",
                    timeout,
                    limiter,
                )
            finally:
                asn_gate.release(asn_key)
        finally:
            net_gate.release(net_key)
        return {
            **c,
            "exposed": pr["exposed"],
            "status": pr["status"],
            "models": pr["models"],
            "probe_detail": pr["detail"],
            "version": pr["version"],
            "error": pr["error"],
            "source": c.get("source") or "multilane",
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(one, c): c for c in cands}
        for i, fut in enumerate(as_completed(futs), 1):
            r = fut.result()
            results.append(r)
            mark = "EXPOSED" if r.get("exposed") else "—"
            cc = r.get("country_code") or "?"
            print(
                f"[{i}/{len(cands)}] {r['ip']}:{r['port']} {r.get('stack')} "
                f"{cc} {mark}"
            )
    return results


def self_test_candidates() -> list[dict]:
    """
    Synthetic candidates for --self-test.

    RFC 5737 documentation space, which is never routed, so even a bug that got
    past --dry-run could not reach a real host. One candidate per governance
    outcome, so the smoke test shows the gates deciding rather than just running.
    """
    return [
        {
            "ip": "203.0.113.10",
            "port": 11434,
            "stack": "ollama",
            "probe_path": "/api/ps",
            "source": "shodan:ollama",
            "asn": "AS64496",
            "country_code": "ZZ",
            "provenance": index_provenance(
                "shodan", "product:Ollama", "ollama", "lane_search"
            ),
        },
        {
            "ip": "203.0.113.11",
            "port": 11434,
            "stack": "ollama",
            "probe_path": "/api/ps",
            "source": "handwritten",
            "asn": "AS64496",
            "country_code": "ZZ",
        },
        {
            "ip": "203.0.113.12",
            "port": 8888,
            "stack": "jupyter",
            "probe_path": "/",
            "source": "curiosity:someone_mentioned_it",
            "asn": "AS64496",
            "country_code": "ZZ",
            "provenance": index_provenance("hearsay", "?", "jupyter", "lane_search"),
        },
        {
            "ip": "198.51.100.7",
            "port": 11434,
            "stack": "prior",
            "probe_path": "/api/ps",
            "source": "prior",
            "asn": "AS64497",
            "country_code": "ZZ",
            # A corpus row whose stored source records our own probe, not an
            # index listing — the circular case I-22 has to refuse.
            "provenance": provenance_from_corpus_source("check"),
        },
        {
            "ip": "198.51.100.8",
            "port": 11434,
            "stack": "ollama",
            "probe_path": "/api/ps",
            "source": "prior",
            "asn": "AS64497",
            "country_code": "ZZ",
            "provenance": provenance_from_corpus_source("shodan_asn:AS64497"),
        },
        {
            "ip": "198.51.100.9",
            "port": 11434,
            "stack": "operator_request",
            "probe_path": "/api/ps",
            "source": "operator_request:not-in-manifest",
            "asn": "AS64497",
            "country_code": "ZZ",
            "provenance": {
                "path": "operator_request",
                "request_id": "not-in-manifest",
            },
        },
    ]


def ingest(api_base: str, token: str, results: list[dict], meta: dict) -> list:
    batch = 100
    outs = []
    for i in range(0, len(results), batch):
        chunk = results[i : i + batch]
        # Slim payload for the worker. Provenance stays on this machine: the
        # corpus retains only the fields I-26 lists, and the run's own record
        # (meta, plus the console log) is where the entitlement is auditable.
        slim = []
        for r in chunk:
            slim.append(
                {
                    "ip": r["ip"],
                    "port": r["port"],
                    "exposed": bool(r.get("exposed")),
                    "models": r.get("models") or [],
                    "source": r.get("source"),
                    "stack": r.get("stack"),
                    # I-26 retains a version string. Sending only `product` left
                    # the stored version permanently null, which switched off
                    # the whole OSV path downstream; the Worker reads `version`
                    # and falls back to parsing the banner out of `product`.
                    "version": r.get("version"),
                    "country": r.get("country"),
                    "country_code": r.get("country_code"),
                    "city": r.get("city"),
                    "asn": r.get("asn"),
                    "org": r.get("org"),
                    "product": r.get("product"),
                    "vulns": r.get("vulns") or [],
                }
            )
        st, data = http_json(
            f"{api_base.rstrip('/')}/v1/admin/discovery/ingest",
            method="POST",
            data={"results": slim, "run_meta": meta},
            headers={"X-Admin-Token": token},
            timeout=120,
        )
        if st != 200:
            raise SystemExit(f"ingest failed: {st} {data}")
        print(f"  ingest batch ok: {data}")
        outs.append(data)
        time.sleep(2.5)
    return outs


def main() -> int:
    ap = argparse.ArgumentParser(description="Multi-lane discovery seed builder")
    ap.add_argument("--api-base", default=os.getenv("LEAKY_API_BASE"))
    ap.add_argument(
        "--admin-token",
        default=os.getenv("LEAKY_ADMIN_TOKEN") or os.getenv("ADMIN_SYNC_TOKEN"),
    )
    ap.add_argument("--shodan-key", default=os.getenv("SHODAN_API_KEY"))
    ap.add_argument("--lanes", default="all", help="Comma ids or 'all'")
    ap.add_argument("--rate", type=float, default=0.2)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=3.5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ingest", action="store_true")
    ap.add_argument("--from-prior", action="store_true", default=True)
    ap.add_argument("--no-prior", action="store_true")
    ap.add_argument("--output", default="data/discovery-multilane.json")
    ap.add_argument("--max-total", type=int, default=320, help="Cap across all lanes")
    ap.add_argument(
        "--approved-requests",
        default=os.getenv("LEAKY_APPROVED_REQUESTS"),
        help="JSON manifest of maintainer-approved operator scan requests (I-22b)",
    )
    ap.add_argument(
        "--reprobe-days",
        type=int,
        default=REPROBE_INTERVAL_DAYS,
        help=f"Minimum days between probe cycles per host (floor {REPROBE_INTERVAL_DAYS}, I-24)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="Run the governance gates against synthetic documentation-range "
        "candidates. Implies --dry-run; contacts no index and no target.",
    )
    args = ap.parse_args()

    if args.self_test:
        # Forced, not merely defaulted: the synthetic corpus exists to exercise
        # the gates, and a mistyped flag must not turn it into a probe run.
        args.dry_run = True

    # I-24 is a floor, not a default. A flag may slow re-verification down, never
    # speed it up.
    args.reprobe_days = max(args.reprobe_days, REPROBE_INTERVAL_DAYS)

    if not args.shodan_key and not (args.dry_run or args.self_test):
        raise SystemExit("SHODAN_API_KEY required")

    # I-22(b): loaded before any Shodan credit is spent, because a broken
    # approval manifest ends the run either way.
    try:
        approved = load_approved_requests(args.approved_requests)
    except ProvenanceUnavailable as e:
        raise SystemExit(f"\n[x] refusing to run: {e}")
    if approved:
        print(f"[+] approved operator scan requests: {len(approved)}")

    want = None if args.lanes == "all" else {x.strip() for x in args.lanes.split(",")}
    lanes = [L for L in LANES if want is None or L["id"] in want]

    all_cands: list[dict] = []
    if args.self_test:
        lanes = []
        all_cands.extend(self_test_candidates())
        print(f"[*] self-test: {len(all_cands)} synthetic candidates, no lanes run")
    elif not args.shodan_key:
        print("[!] no Shodan key — skipping index lanes (dry run emits nothing)")
        lanes = []

    indexed_observed = 0
    for lane in lanes:
        try:
            lane_cands, lane_observed = collect_lane(args.shodan_key, lane)
            all_cands.extend(lane_cands)
            indexed_observed += lane_observed
        except SystemExit as e:
            print(f"  lane {lane['id']} aborted: {e}")
        except Exception as e:
            print(f"  lane {lane['id']} error: {e}")
        time.sleep(1.0)

    # I-22(b): approved requests are the only way a host that no index lists can
    # become a target, and only inside the space its owner attested for.
    all_cands.extend(candidates_for_requests(approved, 11434, "/api/ps"))

    # --- I-24: the hit store is both a candidate source and the last-seen clock
    prior_hits: list[dict] = []
    last_seen: dict[str, str] | None = None
    interval_error: str | None = None
    if args.self_test:
        interval_error = "self-test does not contact the admin API"
    else:
        try:
            prior_hits = fetch_hits(args.api_base, args.admin_token)
            # Both halves or neither: a partial clock is the fail-open case.
            attempts = fetch_probe_clock(args.api_base, args.admin_token)
            last_seen = last_seen_map(prior_hits, attempts)
            print(
                f"\n[+] hit store: {len(prior_hits)} host(s); "
                f"probe clock: {len(attempts)} attempt(s); "
                f"{len(last_seen)} host(s) under the I-24 interval"
            )
        except IntervalDataUnavailable as e:
            prior_hits = []
            last_seen = None
            interval_error = str(e)

    if args.from_prior and not args.no_prior and prior_hits:
        kept = 0
        for h in prior_hits:
            # A corpus row is not its own justification: the entitlement is the
            # index record that put it there (I-22), which survives only as the
            # stored source string. Rows without one are dropped by the gate
            # below rather than quietly re-probed.
            stack = h.get("stack")
            all_cands.append(
                {
                    "ip": h["ip"],
                    "port": h.get("port") or 11434,
                    "stack": stack or "prior",
                    "probe_path": "/api/ps" if not stack or stack == "ollama" else "/",
                    "source": "prior",
                    "provenance": provenance_from_corpus_source(
                        h.get("source"), h.get("first_seen")
                    ),
                    "country": h.get("country"),
                    "country_code": h.get("country_code"),
                    "city": h.get("city"),
                    "asn": h.get("asn"),
                    "org": h.get("org"),
                }
            )
            kept += 1
        print(f"[+] prior hits queued: {kept}")

    # global dedupe
    by_key: dict[str, dict] = {}
    for c in all_cands:
        if not c.get("ip"):
            continue
        k = f"{c['ip']}:{c.get('port')}"
        if k not in by_key:
            by_key[k] = c
        else:
            for f in (
                "country",
                "country_code",
                "city",
                "asn",
                "org",
                "product",
                "stack",
                # A host seen both as a bare corpus row and in a lane keeps the
                # lane's record; merging the other way would drop the entitlement.
                "provenance",
            ):
                if c.get(f) and not by_key[k].get(f):
                    by_key[k][f] = c[f]

    cands = list(by_key.values())[: args.max_total]

    # --- I-22: every target traces to a public index record or an approved
    # operator request. No record → no probe, and the drop is printed rather
    # than counted, because a source that quietly loses its provenance is a
    # source that quietly turns this into a discovery scanner.
    before_prov = len(cands)
    cands, no_provenance = partition_by_provenance(cands, approved)
    drop_reasons = Counter(d["dropped_by"] for d in no_provenance)
    print(f"\n[+] provenance: {len(cands)}/{before_prov} candidate(s) eligible")
    if no_provenance:
        print(f"[x] dropped {len(no_provenance)} candidate(s) with no valid provenance:")
        for d in no_provenance[:10]:
            print(f"    dropped {d['ip']}:{d.get('port')} — {d['dropped_by']}")
        if len(no_provenance) > 10:
            print(f"    … and {len(no_provenance) - 10} more")
        # Also on stderr: unattended runs are the ones where a source silently
        # losing its provenance would otherwise scroll past unread.
        print(
            f"[x] I-22: {len(no_provenance)} candidate(s) dropped — "
            + ", ".join(f"{r}={n}" for r, n in drop_reasons.most_common()),
            file=sys.stderr,
        )

    # --- I-25: exclusions are consulted before any probe is emitted ---------
    # This runs ahead of the dry-run branch as well, so the candidate file we
    # write never contains space someone asked us to leave alone.
    #
    # Fail closed: if we are going to probe and cannot read the list, we stop.
    # A dry run emits no packets, so it may continue with a loud warning.
    excluded: list[dict] = []
    exclusions_applied = False
    try:
        entries = fetch_exclusions(args.api_base, args.admin_token)
        exclusions_applied = True
        before = len(cands)
        cands, excluded = filter_candidates(cands, entries)
        print(
            f"\n[+] exclusions: {len(entries)} rule(s) · "
            f"{before - len(cands)} candidate(s) removed"
        )
        for e in excluded[:20]:
            print(f"    excluded {e['ip']}:{e.get('port')} by {e['excluded_by']}")
        if len(excluded) > 20:
            print(f"    … and {len(excluded) - 20} more")
    except ExclusionsUnavailable as e:
        if args.dry_run:
            print(f"\n[!] exclusion list unavailable ({e})")
            print("[!] dry run continues — no packets are sent to any target.")
            print("[!] the candidate list below is NOT exclusion-filtered.")
        else:
            raise SystemExit(
                f"\n[x] refusing to probe: {e}\n"
                "    I-25 requires the exclusion list to be consulted before any\n"
                "    request is emitted. Fix the API base / admin token, or use\n"
                "    --dry-run, which sends nothing."
            )

    # --- I-24: at most one probe cycle per host per 14 days -----------------
    # Same fail-closed shape as exclusions above: without the last-seen clock we
    # cannot tell a due host from one we probed yesterday, so we do not probe.
    too_soon: list[dict] = []
    if last_seen is None:
        if args.dry_run:
            print(f"\n[!] last-seen data unavailable ({interval_error})")
            print("[!] dry run continues — no packets are sent to any target.")
            print("[!] the candidate list below is NOT interval-filtered.")
        else:
            raise SystemExit(
                f"\n[x] refusing to probe: {interval_error}\n"
                "    I-24 allows one probe cycle per host per "
                f"{args.reprobe_days} days, which needs the hit store's\n"
                "    last-seen data. Fix the API base / admin token, or use\n"
                "    --dry-run, which sends nothing."
            )
    else:
        before_interval = len(cands)
        cands, too_soon = filter_by_interval(cands, last_seen, args.reprobe_days)
        print(
            f"\n[+] re-probe interval ({args.reprobe_days}d): "
            f"{before_interval - len(cands)} host(s) skipped as recently probed"
        )

    # Ordering only — the ceilings in run_probes() do the enforcing.
    cands = spread_by_bucket(cands)

    # country summary of passive set
    cc = Counter(c.get("country_code") or "?" for c in cands)
    print(f"\n[*] Total unique candidates: {len(cands)}")
    print("[*] Countries (passive set):")
    for k, v in cc.most_common(20):
        print(f"    {k}: {v}")

    effective_rate = min(args.rate, RUNNER_MAX_RATE, HARD_MAX_RATE)
    meta = {
        "lanes": [L["id"] for L in lanes],
        "candidate_count": len(cands),
        "excluded_count": len(excluded),
        # Spec §4, second number: hosts a public index listed, counted and not
        # probed (I-21). Reported separately from candidate_count, which is the
        # subset we are willing to send a read-only GET.
        "indexed_observed": indexed_observed,
        "observed_source": "public index records (Shodan lanes), counted not probed",
        # False only ever appears on a dry run, where nothing was probed.
        "exclusion_filtered": exclusions_applied,
        # I-22. Reasons only — the dropped addresses stay on the console, since
        # a run record is no reason to widen how far raw IPs travel (I-14).
        "provenance_enforced": True,
        "provenance_dropped": len(no_provenance),
        "provenance_drop_reasons": dict(drop_reasons),
        "approved_requests": len(approved),
        # I-24.
        "interval_enforced": last_seen is not None,
        "reprobe_interval_days": args.reprobe_days,
        "skipped_recently_probed": len(too_soon),
        "rate": effective_rate,
        "rate_requested": args.rate,
        "max_inflight_per_24": MAX_INFLIGHT_PER_24,
        "max_inflight_per_asn": MAX_INFLIGHT_PER_ASN,
        "mode": "multilane_seed",
    }

    if args.dry_run:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump({"meta": meta, "candidates": cands, "countries": cc.most_common()}, f, indent=2)
            f.write("\n")
        print(f"[+] dry-run wrote {args.output}")
        return 0

    print(f"[*] Probing {len(cands)} hosts @ {effective_rate}/s …")
    results = run_probes(cands, args.rate, args.workers, args.timeout)
    exposed = [r for r in results if r.get("exposed")]
    print(f"[+] exposed={len(exposed)} / {len(results)}")

    # geo of exposed
    ecc = Counter(r.get("country_code") or "?" for r in exposed)
    print("[+] Exposed by country:")
    for k, v in ecc.most_common(25):
        print(f"    {k}: {v}")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(
            {
                "meta": meta,
                "results": results,
                "exposed": exposed,
                "countries_exposed": ecc.most_common(),
                "countries_candidates": cc.most_common(),
            },
            f,
            indent=2,
        )
        f.write("\n")
    print(f"[+] wrote {args.output}")

    if args.ingest:
        if not args.admin_token or not args.api_base:
            raise SystemExit("--ingest needs API base + admin token")
        ingest(args.api_base, args.admin_token, results, meta)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
