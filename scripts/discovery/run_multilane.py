#!/usr/bin/env python3
"""
Multi-lane discovery runner for a solid pre-post seed.

Lanes = high-signal Shodan fingerprints (Ollama, Jupyter-unauth, Ray, Open WebUI, …).
Each lane: passive pull (limited) → stack-aware safe GET → ingest with geo.

Usage:
  export SHODAN_API_KEY=...
  export LEAKY_API_BASE=https://leakycompute-api.mhedhli.workers.dev
  export LEAKY_ADMIN_TOKEN=...

  python3 scripts/discovery/run_multilane.py --dry-run
  python3 scripts/discovery/run_multilane.py --ingest --rate 0.2
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# Reuse helpers from discover.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from discover import (  # noqa: E402
    HARD_MAX_RATE,
    GlobalRateLimiter,
    fetch_prior_hits,
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

USER_AGENT = "LeakyCompute-MultiLane/1.0 (+defensive; safe GET only)"

# Full multi-lane calibration set for seed building
LANES: list[dict[str, Any]] = [
    {
        "id": "ollama",
        "query": "product:Ollama",
        "port_default": 11434,
        "probe_path": "/api/ps",
        "mode": "asn",  # top ASNs
        "top_asns": 12,
        "hosts_per_asn": 6,
        "max_hosts": 48,
    },
    {
        "id": "jupyter",
        "query": 'http.title:"Jupyter" port:8888 -http.html:"token"',
        "port_default": 8888,
        "probe_path": "/",
        "mode": "search",
        "search_limit": 40,
        "max_hosts": 40,
    },
    {
        "id": "ray",
        "query": "port:8265",
        "port_default": 8265,
        "probe_path": "/api/version",
        "mode": "search",
        "search_limit": 40,
        "max_hosts": 40,
    },
    {
        "id": "open_webui",
        "query": 'http.title:"Open WebUI"',
        "port_default": 8080,
        "probe_path": "/",
        "mode": "asn",
        "top_asns": 10,
        "hosts_per_asn": 5,
        "max_hosts": 40,
    },
    {
        "id": "localai",
        "query": 'http.html:"LocalAI"',
        "port_default": 8080,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 30,
        "max_hosts": 30,
    },
    {
        "id": "litellm",
        "query": 'http.html:"LiteLLM"',
        "port_default": 4000,
        "probe_path": "/health",
        "mode": "search",
        "search_limit": 30,
        "max_hosts": 30,
    },
    {
        "id": "vllm",
        "query": 'http.html:"vLLM"',
        "port_default": 8000,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 30,
        "max_hosts": 30,
    },
    {
        "id": "openai_compat_8000",
        "query": 'port:8000 http.html:"/v1/models"',
        "port_default": 8000,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 25,
        "max_hosts": 25,
    },
    {
        "id": "openai_compat_8080",
        "query": 'port:8080 http.html:"/v1/models"',
        "port_default": 8080,
        "probe_path": "/v1/models",
        "mode": "search",
        "search_limit": 25,
        "max_hosts": 25,
    },
    {
        "id": "comfyui",
        "query": 'port:8188 http.title:"ComfyUI"',
        "port_default": 8188,
        "probe_path": "/system_stats",
        "mode": "search",
        "search_limit": 35,
        "max_hosts": 35,
    },
    {
        "id": "gradio",
        "query": 'http.title:"Gradio"',
        "port_default": 7860,
        "probe_path": "/",
        "mode": "search",
        "search_limit": 25,
        "max_hosts": 25,
    },
    {
        "id": "mlflow",
        "query": 'http.title:"MLflow"',
        "port_default": 5000,
        "probe_path": "/",
        "mode": "search",
        "search_limit": 25,
        "max_hosts": 25,
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
        **geo,
    }


def collect_lane(api_key: str, lane: dict) -> list[dict]:
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
    out = list(by_key.values())[: lane.get("max_hosts", 40)]
    print(f"  unique candidates this lane: {len(out)}")
    return out


def safe_probe(ip: str, port: int, path: str, timeout: float, limiter: GlobalRateLimiter) -> dict:
    limiter.wait()
    url = f"http://{ip}:{port}{path}"
    status, payload = http_json(url, timeout=timeout)
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
        elif path in ("/api/version", "/health", "/system_stats"):
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
        "error": None if status else payload,
    }


def run_probes(cands: list[dict], rate: float, workers: int, timeout: float) -> list[dict]:
    limiter = GlobalRateLimiter(min(rate, HARD_MAX_RATE))
    workers = max(1, min(workers, 2))
    results: list[dict] = []

    def one(c: dict):
        pr = safe_probe(
            c["ip"],
            int(c["port"]),
            c.get("probe_path") or "/",
            timeout,
            limiter,
        )
        return {
            **c,
            "exposed": pr["exposed"],
            "status": pr["status"],
            "models": pr["models"],
            "probe_detail": pr["detail"],
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


def ingest(api_base: str, token: str, results: list[dict], meta: dict) -> list:
    batch = 100
    outs = []
    for i in range(0, len(results), batch):
        chunk = results[i : i + batch]
        # slim payload for worker
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
    args = ap.parse_args()

    if not args.shodan_key:
        raise SystemExit("SHODAN_API_KEY required")

    want = None if args.lanes == "all" else {x.strip() for x in args.lanes.split(",")}
    lanes = [L for L in LANES if want is None or L["id"] in want]

    all_cands: list[dict] = []
    for lane in lanes:
        try:
            all_cands.extend(collect_lane(args.shodan_key, lane))
        except SystemExit as e:
            print(f"  lane {lane['id']} aborted: {e}")
        except Exception as e:
            print(f"  lane {lane['id']} error: {e}")
        time.sleep(1.0)

    if args.from_prior and not args.no_prior and args.admin_token and args.api_base:
        prior = fetch_prior_hits(args.api_base, args.admin_token)
        print(f"\n[+] prior hits: {len(prior)}")
        for h in prior:
            all_cands.append(
                {
                    "ip": h["ip"],
                    "port": h.get("port") or 11434,
                    "stack": h.get("stack") or "prior",
                    "probe_path": "/api/ps" if not h.get("stack") or h.get("stack") == "ollama" else "/",
                    "source": "prior",
                    "country": h.get("country"),
                    "country_code": h.get("country_code"),
                    "city": h.get("city"),
                    "asn": h.get("asn"),
                    "org": h.get("org"),
                }
            )

    # global dedupe
    by_key: dict[str, dict] = {}
    for c in all_cands:
        if not c.get("ip"):
            continue
        k = f"{c['ip']}:{c.get('port')}"
        if k not in by_key:
            by_key[k] = c
        else:
            for f in ("country", "country_code", "city", "asn", "org", "product", "stack"):
                if c.get(f) and not by_key[k].get(f):
                    by_key[k][f] = c[f]

    cands = list(by_key.values())[: args.max_total]

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

    # country summary of passive set
    from collections import Counter

    cc = Counter(c.get("country_code") or "?" for c in cands)
    print(f"\n[*] Total unique candidates: {len(cands)}")
    print("[*] Countries (passive set):")
    for k, v in cc.most_common(20):
        print(f"    {k}: {v}")

    meta = {
        "lanes": [L["id"] for L in lanes],
        "candidate_count": len(cands),
        "excluded_count": len(excluded),
        # False only ever appears on a dry run, where nothing was probed.
        "exclusion_filtered": exclusions_applied,
        "rate": args.rate,
        "mode": "multilane_seed",
    }

    if args.dry_run:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump({"meta": meta, "candidates": cands, "countries": cc.most_common()}, f, indent=2)
            f.write("\n")
        print(f"[+] dry-run wrote {args.output}")
        return 0

    print(f"[*] Probing {len(cands)} hosts @ {args.rate}/s …")
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
