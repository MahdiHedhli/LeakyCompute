#!/usr/bin/env python3
"""
LeakyCompute legacy passive discovery helper.

Important: archive seed (data/seed-models.json) has MODEL NAMES + counts only —
NO IPs. ASN / hosting-provider seeding comes from:
  • Shodan facets (top ASNs for Ollama-like queries)
  • Shodan host matches (with org/asn fields)
  • Prior exposed hits stored privately in the Worker
  • Optional local seeds file

Historical pipeline (active stages disabled):
  1) Passive: Shodan search + ASN facet report
  2) Optional: pull top ASNs and fetch limited hosts per ASN
  3) Prior hits from Worker admin API
  4) Optional tiny neighborhood expand (/29–/30 only by default policy)
  5) Former active probe and ingest stages — now disabled

Use this helper only for passive reports and dry-run plans. Any non-dry active
invocation exits before sending a target request.

Examples:
  export SHODAN_API_KEY=...
  export LEAKY_API_BASE=https://api.leakycompute.mahdihedhli.com
  export LEAKY_ADMIN_TOKEN=...

  # ASN report only (passive, 1 credit-ish)
  python3 scripts/discovery/discover.py --asn-report --shodan-query 'port:11434'

  # Seed from top hosting ASNs, dry-run targets
  python3 scripts/discovery/discover.py \\
      --from-top-asns 15 --hosts-per-asn 10 \\
      --from-prior --max-total 64 --dry-run

  # Active modes are intentionally unavailable in this legacy helper.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

DEFAULT_API = "https://api.leakycompute.mahdihedhli.com"
# product:Ollama is the high-signal Shodan fingerprint (~12k hosts).
# Banner-only queries often return 0 depending on how banners are indexed.
DEFAULT_QUERY = "product:Ollama"
FALLBACK_QUERY = 'port:11434 http.html:"Ollama is running"'
USER_AGENT = "LeakyCompute-Discovery/1.0 (+defensive research; safe GET /api/ps only)"

# I-23 promises an operator one search. That only works if the packet says what
# the /scanning page says it says, so anything aimed at a third-party target
# goes out under this — the same prefix the Worker's probe uses. USER_AGENT
# above stays for calls to our own API and to Shodan, which are not probes.
PROBE_USER_AGENT = "LeakyCompute-SafeProbe/1.0 (+defensive research; read-only GET)"
MAX_RESPONSE_BYTES = 32 * 1024

# Hard safety rails (cannot be overridden above these without editing code).
# The governed workflow may nominate up to one free-tier-safe daily envelope,
# but commits that envelope to the strong control plane in transactions of at
# most 128 records. Keep the run ceiling distinct from that transaction bound.
HARD_MAX_TOTAL = 425
# Incremental pages walked per search lane per scheduled invocation. The
# strongly consistent source ledger separately paces every request across the
# configured month. A local operator may lower this, never raise it above the
# reviewed hard bound without editing code.
PAGES_PER_RUN = 1
HARD_MAX_PAGES_PER_LANE = 10
# ASN lanes buy one facet page plus a small rotating slice of provider groups.
ASN_GROUPS_PER_RUN = 2
# A passive source outage must not consume an entire scheduled run, but retrying
# forever would hide a persistent provider or query failure and could burn
# credits. Each page therefore gets one request plus two bounded retries.
SHODAN_MAX_ATTEMPTS = 3
SHODAN_RETRY_BASE_SECONDS = 2.0
SHODAN_RETRY_MAX_SECONDS = 8.0
HARD_MAX_RATE = 1.0  # probes/sec global absolute ceiling
HARD_MIN_PREFIX = 28  # never expand wider than /28
HARD_MAX_HOSTS_PER_ASN = 25
HARD_MAX_ASNS = 30


class ShodanRequestError(SystemExit):
    """Public-safe provider failure with a machine-readable category."""

    def __init__(self, category: str, attempts: int):
        self.category = category
        self.attempts = attempts
        super().__init__(f"Shodan search failed: {category}; attempts={attempts}")


class GlobalRateLimiter:
    """Process-wide min-interval limiter (shared across threads)."""

    def __init__(self, rate_per_sec: float):
        rate = max(0.05, min(float(rate_per_sec), HARD_MAX_RATE))
        self._interval = 1.0 / rate
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self._interval


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """
    I-6, off-Worker half.

    urlopen()'s default opener follows 301/302/303/307 silently, so a probed
    host could answer with `Location:` and aim our next GET wherever it liked —
    an address in no public index (I-22) at a path no one reviewed (I-2). From
    the far end that makes this a request reflector pointed by the target, which
    is the shape the Worker has refused since it shipped (`redirect: "manual"`
    in services.js). Returning None here surfaces the 3xx as the response
    instead of chasing it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def http_json(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    headers: dict | None = None,
    timeout: float = 30.0,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> tuple[int | None, Any]:
    body = None if data is None else json.dumps(data).encode()
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        # No opt-out parameter on purpose. Every caller here either probes a
        # third-party target or talks to our own API; neither needs to be
        # redirected, and a flag is one edit away from the target choosing.
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(max_response_bytes + 1)[:max_response_bytes].decode(
                "utf-8", errors="replace"
            )
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = (
            e.read(max_response_bytes + 1)[:max_response_bytes].decode(
                "utf-8", errors="replace"
            )
            if e.fp
            else ""
        )
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return None, str(e)


def payload_shape(payload: Any) -> str:
    """Describe an API response without logging its untrusted contents."""
    if isinstance(payload, dict):
        keys = sorted(str(key)[:40] for key in payload.keys())[:20]
        return f"object keys={keys}"
    if isinstance(payload, list):
        return f"array length={len(payload)}"
    if isinstance(payload, str):
        return f"text length={len(payload)}"
    return type(payload).__name__


def shodan_failure_category(status: int | None, payload: Any) -> tuple[str, bool]:
    """Return a public-safe failure category and whether retrying is safe.

    Response bodies and transport exception strings are deliberately ignored:
    Shodan banners and provider messages do not belong in public workflow logs.
    Only failures that are plausibly transient are retried. Authentication,
    query, redirect, and malformed-response failures need operator attention and
    fail the lane immediately.
    """
    if status is None:
        return "transport_error", True
    if status in {408, 425}:
        return "transient_request_error", True
    if status == 429:
        return "rate_limited", True
    if 500 <= status <= 599:
        return "upstream_server_error", True
    if status in {401, 403}:
        return "authentication_rejected", False
    if 400 <= status <= 499:
        return "request_rejected", False
    if 300 <= status <= 399:
        return "redirect_refused", False
    if 200 <= status <= 299 and not isinstance(payload, dict):
        return "malformed_response", False
    return "unexpected_response", False


def shodan_json_with_retry(
    url: str,
    *,
    budget_consumer=None,
    retry_sleep=time.sleep,
    retry_jitter=random.uniform,
) -> dict:
    """Fetch one Shodan page with bounded full-jitter transient retries."""
    for attempt in range(1, SHODAN_MAX_ATTEMPTS + 1):
        if budget_consumer is not None:
            # Ambiguous requests remain charged: consume the strong monthly
            # source unit immediately before the provider call and never refund
            # based on a response we may not have received.
            budget_consumer()
        status, payload = http_json(
            url,
            timeout=60,
            max_response_bytes=256 * 1024,
        )
        if status == 200 and isinstance(payload, dict):
            return payload

        category, retryable = shodan_failure_category(status, payload)
        if not retryable or attempt == SHODAN_MAX_ATTEMPTS:
            raise ShodanRequestError(category, attempt)

        ceiling = min(
            SHODAN_RETRY_MAX_SECONDS,
            SHODAN_RETRY_BASE_SECONDS * (2 ** (attempt - 1)),
        )
        delay = min(ceiling, max(0.0, float(retry_jitter(0.0, ceiling))))
        print(
            f"[!] Shodan transient failure: {category}; "
            f"retrying attempt {attempt + 1}/{SHODAN_MAX_ATTEMPTS} "
            f"after {delay:.1f}s"
        )
        retry_sleep(delay)

    raise AssertionError("unreachable Shodan retry state")


def probe_ollama(ip: str, port: int, timeout: float, limiter: GlobalRateLimiter) -> dict:
    limiter.wait()
    status, payload = http_json(
        f"http://{ip}:{port}/api/ps",
        timeout=timeout,
        headers={"User-Agent": PROBE_USER_AGENT},
    )
    if status == 200 and isinstance(payload, dict):
        models = payload.get("models") or []
        return {
            "ip": ip,
            "port": port,
            "exposed": True,
            "status": status,
            "models": [
                {"name": m.get("name") or m.get("model"), "size": m.get("size")}
                for m in models[:25]
            ],
            "source": "active_probe",
        }
    return {
        "ip": ip,
        "port": port,
        "exposed": False,
        "status": status,
        "models": [],
        "error": None if status else payload,
        "source": "active_probe",
    }


def shodan_search(
    api_key: str,
    query: str,
    limit: int,
    *,
    facets: str | None = None,
    start_page: int = 1,
    pages_per_run: int = PAGES_PER_RUN,
    budget_consumer=None,
) -> tuple[list[dict], dict, int]:
    """
    Shodan host search. Returns (matches, facet_dict, next_page).

    start_page exists because this opened at page 1 on every invocation, so
    consecutive runs bought the same first hundred results over and over: the
    corpus stopped growing while query credits still drained. The caller keeps a
    per-lane cursor and walks down the result set instead of re-reading the top.

    next_page is where the caller should resume. It comes back as 1 when the
    lane is exhausted, which is a deliberate wrap rather than a stop: the index
    changes underneath us, so the top of the list next month is not the list we
    already hold.
    """
    page_cap = max(1, min(int(pages_per_run), HARD_MAX_PAGES_PER_LANE))
    out: list[dict] = []
    facets_out: dict = {}
    exhausted = False
    index_total = None
    page = max(1, int(start_page))
    while len(out) < limit:
        params: dict[str, Any] = {
            "key": api_key,
            "query": query,
            "page": page,
            # Shodan introduced `fields` in 2026 and documents it as mutually
            # exclusive with minify. `minify=false` plus an explicit allowlist
            # still returns less data than minify alone, without the API 400.
            "minify": "false",
            # Shodan banners can contain entire model configurations and other
            # operator data. Request only the fields needed to nominate and
            # contextualise a candidate; never download or log banner bodies.
            "fields": (
                "ip_str,port,asn,org,isp,product,version,timestamp,"
                "location"
            ),
        }
        if facets and page == 1:
            params["facets"] = facets
        url = "https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode(params)
        data = shodan_json_with_retry(url, budget_consumer=budget_consumer)
        # `total` rides on every page, not just the first. Reading it only in
        # the page==1 branch left it None for every lane that resumed from a
        # cursor — which is every lane after the first run.
        _t = data.get("total")
        if isinstance(_t, int):
            index_total = _t
        if page == 1:
            facets_out = data.get("facets") or {}
            print(f"[*] Shodan total matching query: {index_total}")
        matches = data.get("matches") or []
        if not matches:
            break
        for m in matches:
            ip = m.get("ip_str")
            if not ip:
                continue
            # ASN may be int or str like "AS15169"
            asn_raw = m.get("asn") or ""
            if isinstance(asn_raw, int):
                asn = f"AS{asn_raw}"
            else:
                asn = str(asn_raw)
            loc = m.get("location") or {}
            out.append(
                {
                    "ip": ip,
                    "port": int(m.get("port") or 11434),
                    "source": "shodan",
                    "org": m.get("org"),
                    "isp": m.get("isp"),
                    "asn": asn,
                    "product": (m.get("product") or ""),
                    "version": (m.get("version") or ""),
                    "timestamp": m.get("timestamp"),
                    "country": loc.get("country_name"),
                    "country_code": loc.get("country_code"),
                    "city": loc.get("city"),
                    "lat": loc.get("latitude"),
                    "lon": loc.get("longitude"),
                    "location": loc,
                }
            )
            if len(out) >= limit:
                break
        # A short page means the result set ran out under us. Recording it here
        # is what lets the caller wrap its cursor back to 1 instead of paging
        # forever into empty responses, each of which still costs a credit.
        if len(matches) < 100:
            exhausted = True
            page = 0  # signals wrap; normalised below
            break
        page += 1
        # Walk at most PAGES_PER_RUN pages per lane per invocation. The cap is
        # per run, not absolute: the cursor carries the position forward, so
        # successive runs continue down the list rather than restarting it.
        if page - start_page >= page_cap:
            break
        time.sleep(1.25)  # slow Shodan pagination

    next_page = 1 if exhausted or page < 1 else page
    # index_total is what Shodan says the query matches *in the index*, not what
    # we paid to pull. It arrives with page 1 at no extra cost, and it is the
    # only figure here that is a measurement of the exposed population rather
    # than a measurement of our budget.
    return out, facets_out, next_page, index_total


def parse_asn_facets(facets: dict) -> list[dict]:
    """Normalize Shodan asn facet into [{asn, count}, ...]."""
    rows = facets.get("asn") or []
    out = []
    for row in rows:
        # shape: {"value": "AS15169", "count": 123} or similar
        val = row.get("value") or row.get("asn") or ""
        count = int(row.get("count") or 0)
        if not val:
            continue
        if not str(val).upper().startswith("AS"):
            val = f"AS{val}"
        out.append({"asn": str(val).upper(), "count": count})
    return out


def parse_org_facets(facets: dict) -> list[dict]:
    rows = facets.get("org") or []
    return [
        {"org": r.get("value") or "", "count": int(r.get("count") or 0)}
        for r in rows
        if r.get("value")
    ]


def hosts_for_asn(
    api_key: str,
    base_query: str,
    asn: str,
    limit: int,
    *,
    pages_per_run: int = PAGES_PER_RUN,
    budget_consumer=None,
) -> list[dict]:
    """Passive: limited hosts for one ASN (hosting-provider block seed)."""
    limit = min(limit, HARD_MAX_HOSTS_PER_ASN)
    # Shodan filter: asn:AS####
    q = f"{base_query} asn:{asn}"
    matches, _, _, _ = shodan_search(
        api_key,
        q,
        limit,
        facets=None,
        pages_per_run=pages_per_run,
        budget_consumer=budget_consumer,
    )
    for m in matches:
        m["source"] = f"shodan_asn:{asn}"
        m["asn"] = asn
    return matches


def fetch_prior_hits(api_base: str, admin_token: str, limit: int = 500) -> list[dict]:
    status, data = http_json(
        f"{api_base.rstrip('/')}/v1/admin/discovery/hits?limit={limit}",
        headers={"X-Admin-Token": admin_token},
    )
    if status != 200 or not isinstance(data, dict):
        print(f"[!] prior hits fetch failed: {status} {data}", file=sys.stderr)
        return []
    return data.get("hits") or []


def expand_neighborhoods(
    seeds: list[str],
    prefix: int,
    max_per_seed: int,
    max_total: int,
) -> list[str]:
    if prefix < HARD_MIN_PREFIX or prefix > 32:
        raise SystemExit(f"--expand-prefix must be {HARD_MIN_PREFIX}-32 (small neighborhoods only)")
    seen: set[str] = set()
    out: list[str] = []
    for ip_s in seeds:
        if len(out) >= max_total:
            break
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        if ip.version != 4:
            if ip_s not in seen:
                seen.add(ip_s)
                out.append(ip_s)
            continue
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        hosts = [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
        ordered = [ip_s] + [h for h in hosts if h != ip_s]
        n = 0
        for h in ordered:
            if h in seen:
                continue
            seen.add(h)
            out.append(h)
            n += 1
            if n >= max_per_seed or len(out) >= max_total:
                break
    return out


def load_seeds_file(path: str) -> list[str]:
    text = open(path).read().strip()
    if not text:
        return []
    if text[0] in "[{":
        data = json.loads(text)
        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                return [d.get("ip") for d in data if d.get("ip")]
            return [str(x) for x in data]
        if isinstance(data, dict):
            hits = data.get("hits") or data.get("ips") or data.get("candidates") or []
            return [h.get("ip") if isinstance(h, dict) else str(h) for h in hits]
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]


def aggregate_asn_from_candidates(cands: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    orgs: dict[str, str] = {}
    for c in cands:
        asn = (c.get("asn") or "").upper()
        if not asn:
            continue
        counts[asn] = counts.get(asn, 0) + 1
        if c.get("org"):
            orgs[asn] = c["org"]
    rows = [
        {"asn": a, "observed_candidates": n, "org_example": orgs.get(a)}
        for a, n in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
    return rows


def run_probes(
    targets: list[tuple[str, int]],
    rate: float,
    workers: int,
    timeout: float,
) -> list[dict]:
    limiter = GlobalRateLimiter(rate)
    workers = max(1, min(workers, 2))  # hard cap concurrency for free-tier politeness
    results: list[dict] = []

    def one(item: tuple[str, int]):
        ip, port = item
        return probe_ollama(ip, port, timeout, limiter)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(one, t): t for t in targets}
        for i, fut in enumerate(as_completed(futs), 1):
            r = fut.result()
            results.append(r)
            mark = "EXPOSED" if r.get("exposed") else "—"
            print(f"[{i}/{len(targets)}] {r['ip']}:{r['port']} {mark}")
    return results


def ingest(api_base: str, admin_token: str, results: list[dict], meta: dict) -> Any:
    # Keep batches small for free-tier Worker CPU/KV writes
    batch_size = 100
    summaries = []
    for i in range(0, len(results), batch_size):
        chunk = results[i : i + batch_size]
        status, data = http_json(
            f"{api_base.rstrip('/')}/v1/admin/discovery/ingest",
            method="POST",
            data={"results": chunk, "run_meta": meta},
            headers={"X-Admin-Token": admin_token},
            timeout=120,
        )
        if status != 200:
            raise SystemExit(f"ingest failed at offset {i}: HTTP {status} {data}")
        summaries.append(data)
        print(f"[+] ingested batch {i // batch_size + 1}: {data}")
        time.sleep(2.0)  # pause between Worker writes
    return summaries


def main() -> int:
    p = argparse.ArgumentParser(
        description="LeakyCompute passive reporting and dry-run planning helper"
    )
    p.add_argument("--api-base", default=os.getenv("LEAKY_API_BASE", DEFAULT_API))
    p.add_argument(
        "--admin-token",
        default=os.getenv("LEAKY_ADMIN_TOKEN") or os.getenv("ADMIN_SYNC_TOKEN"),
    )
    p.add_argument("--shodan", action="store_true", help="Pull candidates from Shodan search")
    p.add_argument("--shodan-key", default=os.getenv("SHODAN_API_KEY"))
    p.add_argument("--shodan-query", default=DEFAULT_QUERY)
    p.add_argument("--shodan-limit", type=int, default=25)
    p.add_argument(
        "--asn-report",
        action="store_true",
        help="Passive only: print top ASNs/orgs for the Shodan query (facets)",
    )
    p.add_argument(
        "--from-top-asns",
        type=int,
        default=0,
        metavar="N",
        help="After facet report, pull limited hosts from top N ASNs (hosting providers)",
    )
    p.add_argument(
        "--hosts-per-asn",
        type=int,
        default=8,
        help="Max Shodan hosts to pull per ASN (capped)",
    )
    p.add_argument("--from-prior", action="store_true", help="Load prior exposed hits from Worker")
    p.add_argument("--seeds-file", help="Local JSON/list of seed IPs")
    p.add_argument(
        "--expand-prefix",
        type=int,
        default=0,
        help="If 28-32, expand each seed (prefer 29-30). Wider than /28 blocked.",
    )
    p.add_argument("--max-expand-per-seed", type=int, default=4)
    p.add_argument(
        "--max-total",
        type=int,
        default=48,
        help=f"Hard cap on hosts probed this run (code max {HARD_MAX_TOTAL})",
    )
    p.add_argument("--port", type=int, default=11434)
    p.add_argument(
        "--rate",
        type=float,
        default=0.25,
        help=f"Global probes/sec (default 0.25 = 1 every 4s; code max {HARD_MAX_RATE})",
    )
    p.add_argument("--workers", type=int, default=1, help="Concurrent probe threads (max 2)")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--dry-run", action="store_true", help="List targets only; no probes")
    p.add_argument(
        "--ingest",
        action="store_true",
        help="disabled compatibility flag; active ingest is suspended",
    )
    p.add_argument("--output", help="Write full JSON results to path")
    p.add_argument(
        "--asn-output",
        default="data/asn-candidates.json",
        help="Where to write ASN report / block candidates",
    )
    args = p.parse_args()

    active_sources = bool(
        args.shodan
        or args.from_top_asns
        or args.from_prior
        or args.seeds_file
    )
    if (active_sources or args.ingest) and not args.dry_run:
        raise SystemExit(
            "Active probing is disabled in legacy discover.py: it does not "
            "enforce the current I-22/I-24/I-25 governance gates. Use "
            "scripts/discovery/run_multilane.py, or add --dry-run for a "
            "packet-free passive plan."
        )

    # Clamp safety rails
    args.max_total = max(1, min(args.max_total, HARD_MAX_TOTAL))
    args.rate = max(0.05, min(args.rate, HARD_MAX_RATE))
    args.workers = max(1, min(args.workers, 2))
    args.hosts_per_asn = max(1, min(args.hosts_per_asn, HARD_MAX_HOSTS_PER_ASN))
    args.from_top_asns = max(0, min(args.from_top_asns, HARD_MAX_ASNS))
    args.shodan_limit = max(1, min(args.shodan_limit, 100))

    need_shodan = args.shodan or args.asn_report or args.from_top_asns > 0
    if need_shodan and not args.shodan_key:
        raise SystemExit("SHODAN_API_KEY / --shodan-key required for Shodan/ASN modes")

    candidates: list[dict] = []
    asn_rows: list[dict] = []
    org_rows: list[dict] = []

    # --- Passive ASN report / facet pull ---
    if args.asn_report or args.from_top_asns > 0:
        print(f"[*] Shodan facet report for: {args.shodan_query!r}")
        # 1 result page is enough to get facets; limit=1 still returns facets
        sample, facets, _, _ = shodan_search(
            args.shodan_key,
            args.shodan_query,
            limit=max(1, min(args.shodan_limit, 10)),
            facets="asn:25,org:25",
        )
        asn_rows = parse_asn_facets(facets)
        org_rows = parse_org_facets(facets)
        if not asn_rows and sample:
            # fallback: aggregate ASN from sample matches
            asn_rows = [
                {"asn": a["asn"], "count": a["observed_candidates"]}
                for a in aggregate_asn_from_candidates(sample)
            ]
        print("[+] Top ASNs (hosting providers likely):")
        for row in asn_rows[:20]:
            print(f"    {row.get('asn')}: {row.get('count')}")
        print("[+] Top orgs:")
        for row in org_rows[:15]:
            print(f"    {row.get('org')}: {row.get('count')}")

        report = {
            "query": args.shodan_query,
            "generated_note": (
                "Archive seed models have no IPs. ASN candidates come from Shodan facets "
                "and observed hosts — use these ASNs as active-scan block seeds, not the whole ASN."
            ),
            "asns": asn_rows,
            "orgs": org_rows,
            "sample_hosts": sample[:20],
        }
        os.makedirs(os.path.dirname(args.asn_output) or ".", exist_ok=True)
        with open(args.asn_output, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"[+] Wrote ASN report → {args.asn_output}")

        if args.asn_report and not args.shodan and not args.from_top_asns and not args.from_prior and not args.seeds_file:
            return 0

    # --- Seed from top ASNs (passive Shodan, then active later) ---
    if args.from_top_asns > 0:
        if not asn_rows:
            # obtain facets if we skipped report path
            _, facets, _, _ = shodan_search(
                args.shodan_key, args.shodan_query, limit=1, facets="asn:25"
            )
            asn_rows = parse_asn_facets(facets)
        top = asn_rows[: args.from_top_asns]
        print(f"[*] Pulling ≤{args.hosts_per_asn} hosts from top {len(top)} ASNs…")
        for row in top:
            asn = row["asn"]
            try:
                hosts = hosts_for_asn(
                    args.shodan_key, args.shodan_query, asn, args.hosts_per_asn
                )
            except SystemExit as e:
                # try broader query for this ASN
                print(f"[!] {asn}: {e}; trying fallback query")
                hosts = hosts_for_asn(
                    args.shodan_key, FALLBACK_QUERY, asn, args.hosts_per_asn
                )
            print(f"    {asn}: {len(hosts)} hosts")
            candidates.extend(hosts)
            time.sleep(1.0)

    if args.shodan:
        print(f"[*] Shodan search: {args.shodan_query!r} limit={args.shodan_limit}")
        matches, facets, _, _ = shodan_search(
            args.shodan_key,
            args.shodan_query,
            args.shodan_limit,
            facets="asn:15,org:15",
        )
        candidates.extend(matches)
        if not asn_rows:
            asn_rows = parse_asn_facets(facets)
        print(f"[+] Shodan candidates: {len(matches)}")

    if args.from_prior:
        if not args.admin_token:
            raise SystemExit("--admin-token required with --from-prior")
        prior = fetch_prior_hits(args.api_base, args.admin_token)
        print(f"[+] Prior hits from API: {len(prior)}")
        for h in prior:
            candidates.append(
                {
                    "ip": h["ip"],
                    "port": h.get("port") or args.port,
                    "source": "prior",
                    "asn": h.get("asn"),
                }
            )

    if args.seeds_file:
        seeds = load_seeds_file(args.seeds_file)
        print(f"[+] Seeds file: {len(seeds)}")
        for ip in seeds:
            candidates.append({"ip": ip, "port": args.port, "source": "seeds_file"})

    # Dedupe by IP
    by_ip: dict[str, dict] = {}
    for c in candidates:
        ip = c.get("ip")
        if not ip:
            continue
        prev = by_ip.get(ip)
        if not prev:
            by_ip[ip] = c
        else:
            # keep richest metadata
            for k, v in c.items():
                if v and not prev.get(k):
                    prev[k] = v

    seed_ips = list(by_ip.keys())
    if not seed_ips:
        raise SystemExit(
            "No candidates.\n"
            "Note: data/seed-models.json has model names only (no IPs).\n"
            "Use --asn-report / --from-top-asns / --shodan / --from-prior / --seeds-file."
        )

    # ASN summary from observed candidates (for block planning)
    observed_asn = aggregate_asn_from_candidates(list(by_ip.values()))
    if observed_asn:
        print("[+] ASNs among current candidate set:")
        for row in observed_asn[:15]:
            print(
                f"    {row['asn']}: {row['observed_candidates']} "
                f"({row.get('org_example') or '?'})"
            )
        # merge into asn-output for later runs
        try:
            existing = {}
            if os.path.exists(args.asn_output):
                existing = json.loads(open(args.asn_output).read())
            existing["observed_from_candidates"] = observed_asn
            existing["candidate_count"] = len(by_ip)
            with open(args.asn_output, "w") as f:
                json.dump(existing, f, indent=2)
                f.write("\n")
        except Exception as e:
            print(f"[!] could not update asn-output: {e}", file=sys.stderr)

    if args.expand_prefix:
        print(
            f"[*] Expanding neighborhoods /{args.expand_prefix} "
            f"(max {args.max_expand_per_seed}/seed, total cap {args.max_total})"
        )
        expanded = expand_neighborhoods(
            seed_ips,
            args.expand_prefix,
            args.max_expand_per_seed,
            args.max_total,
        )
        for ip in expanded:
            by_ip.setdefault(
                ip, {"ip": ip, "port": args.port, "source": "neighborhood"}
            )
        print(f"[+] After expansion: {len(by_ip)} unique hosts")

    targets = list(by_ip.values())[: args.max_total]
    target_tuples = [(t["ip"], int(t.get("port") or args.port)) for t in targets]

    # Estimate runtime for operator awareness
    est_sec = len(target_tuples) / max(args.rate, 0.05)
    print(
        f"[*] Plan: {len(target_tuples)} hosts @ {args.rate}/s "
        f"~{est_sec/60:.1f} min (workers={args.workers})"
    )

    meta = {
        "shodan": bool(args.shodan) or args.from_top_asns > 0,
        "shodan_query": args.shodan_query if need_shodan else None,
        "from_prior": bool(args.from_prior),
        "from_top_asns": args.from_top_asns or None,
        "hosts_per_asn": args.hosts_per_asn if args.from_top_asns else None,
        "expand_prefix": args.expand_prefix or None,
        "candidate_count": len(targets),
        "max_total": args.max_total,
        "rate": args.rate,
        "workers": args.workers,
        "note": "Archive seed has no IPs; ASN seeds from Shodan facets + prior hits.",
    }

    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "meta": meta,
                    "asn_preview": observed_asn[:10],
                    "targets": targets[:40],
                    "total": len(targets),
                },
                indent=2,
            )
        )
        if args.output:
            with open(args.output, "w") as f:
                json.dump({"meta": meta, "targets": targets, "asns": observed_asn}, f, indent=2)
                f.write("\n")
        return 0

    print(f"[*] Probing {len(target_tuples)} hosts (safe GET /api/ps only)…")
    results = run_probes(target_tuples, args.rate, args.workers, args.timeout)
    exposed = [r for r in results if r.get("exposed")]
    print(f"[+] Done. exposed={len(exposed)} / total={len(results)}")

    payload = {"meta": meta, "results": results, "exposed": exposed, "asns": observed_asn}
    if args.output:
        with open(args.output, "w") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
        print(f"[+] Wrote {args.output}")

    if args.ingest:
        if not args.admin_token:
            raise SystemExit("--admin-token required with --ingest")
        summary = ingest(args.api_base, args.admin_token, results, meta)
        print(f"[+] Ingest complete: {summary}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
