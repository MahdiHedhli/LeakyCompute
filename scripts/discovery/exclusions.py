"""
Scanning exclusion list for the discovery runner — I-25.

The Worker is the source of truth (worker/src/lib/exclusions.js); this module
fetches it and filters candidates before any probe is emitted.

The important property here is **fail closed**. If the exclusion list cannot be
retrieved, the runner must not probe. An opt-out that silently stops being
consulted when the network hiccups is not an opt-out — it is a promise that
degrades to nothing exactly when nobody is watching.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request


class ExclusionsUnavailable(RuntimeError):
    """Raised when the list cannot be fetched. Callers must not probe."""


def fetch_exclusions(api_base: str, token: str, timeout: float = 10.0) -> list[dict]:
    if not api_base or not token:
        raise ExclusionsUnavailable(
            "api_base and admin token are required to read the exclusion list"
        )
    url = f"{api_base.rstrip('/')}/v1/admin/exclusions"
    req = urllib.request.Request(
        url,
        headers={
            "X-Admin-Token": token,
            "Accept": "application/json",
            "User-Agent": "LeakyCompute-MultiLane/1.0 (+defensive; safe GET only)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise ExclusionsUnavailable(f"could not fetch exclusion list: {e}") from e
    except json.JSONDecodeError as e:
        raise ExclusionsUnavailable(f"exclusion list was not valid JSON: {e}") from e

    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ExclusionsUnavailable("exclusion list response had no entries array")
    return entries


def _norm_asn(v) -> str | None:
    s = str(v or "").strip().lower()
    if s.startswith("as"):
        s = s[2:]
    return f"AS{int(s)}" if s.isdigit() else None


def _compile(entries: list[dict]):
    nets, asns = [], set()
    for e in entries or []:
        if not isinstance(e, dict) or e.get("active") is False:
            continue
        t, v = e.get("type"), e.get("value")
        if t == "asn":
            a = _norm_asn(v)
            if a:
                asns.add(a)
        elif t in ("cidr4", "cidr6"):
            try:
                nets.append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                # A rule we cannot parse is a rule we cannot honour. Surface it
                # rather than skipping quietly.
                raise ExclusionsUnavailable(f"unparseable exclusion entry: {v!r}")
    return nets, asns


def filter_candidates(cands: list[dict], entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Split candidates into (allowed, excluded).

    A candidate whose address will not parse is treated as excluded — we do not
    send packets at something we could not evaluate.
    """
    nets, asns = _compile(entries)
    allowed, excluded = [], []
    for c in cands:
        ip_raw = c.get("ip")
        asn = _norm_asn(c.get("asn"))
        if asn and asn in asns:
            excluded.append({**c, "excluded_by": asn})
            continue
        try:
            ip = ipaddress.ip_address(str(ip_raw))
        except ValueError:
            excluded.append({**c, "excluded_by": "unparseable_address"})
            continue
        hit = next((n for n in nets if ip in n), None)
        if hit is not None:
            excluded.append({**c, "excluded_by": str(hit)})
        else:
            allowed.append(c)
    return allowed, excluded
