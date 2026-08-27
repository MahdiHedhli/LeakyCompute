"""
Provenance enforcement for the discovery runner — I-22.

I-22 says we never discover a host by probing: every active target must already
appear in a public index, or belong to someone who asked us to scan it. Until
now the runner *assumed* that, because Shodan was the only lane wired up. An
assumption holds until someone adds a lane; a check holds afterwards too, and
I-22 is the invariant the spec leans on to justify raising volume, so it has to
survive the person who adds the next source.

The rule enforced here: a candidate reaches the probe loop only if it carries a
provenance record that names where it came from and that record still verifies
at probe time. No record, unrecognised source, or an operator request whose
approval does not actually cover the address → dropped, and said out loud. Every
ambiguous case resolves toward not probing, the same bias as exclusions.py.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone

PATH_PUBLIC_INDEX = "public_index"  # I-22(a)
PATH_OPERATOR_REQUEST = "operator_request"  # I-22(b)

# Sources whose records are already published to anyone who asks. Probing a
# host these list reveals nothing our traffic was the first to find. Adding a
# name here is a scope decision (I-21: within the source's terms) — it is not a
# formatting detail, which is why the set is explicit rather than a substring
# test on whatever the lane happened to call itself.
PUBLIC_INDEXES = frozenset({"shodan", "censys"})

# An approval is permission to scan now, not a standing licence. Address space
# changes hands; a year-old ticket is not evidence that today's occupant asked
# for anything.
APPROVAL_MAX_AGE_DAYS = 90
# A stored source label is not standing proof that the index still lists the
# host. Active probing is currently suspended, but this gate must already be
# correct before it can be re-enabled.
MAX_INDEX_PROVENANCE_AGE_DAYS = 7

# I-22a: a requester may only attest for space they control. Nobody controls a
# /8 and needs us to find their Ollama box in it, so an oversized scope is
# treated as a bad-faith request rather than a generous one.
MIN_REQUEST_PREFIX4 = 16
MIN_REQUEST_PREFIX6 = 32


class ProvenanceUnavailable(RuntimeError):
    """Raised when approved-request data cannot be trusted. Callers must not probe."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value) -> datetime | None:
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Building provenance records
# ---------------------------------------------------------------------------


def index_provenance(index: str, query: str, lane: str, via: str, observed_at=None) -> dict:
    """Record for I-22(a): this host was read out of a public index listing."""
    if isinstance(observed_at, datetime):
        ts = observed_at.isoformat()
    elif observed_at:
        ts = str(observed_at)
    else:
        ts = _now().isoformat()
    return {
        "path": PATH_PUBLIC_INDEX,
        "index": str(index or "").strip().lower(),
        "query": query,
        "lane": lane,
        "via": via,
        "observed_at": ts,
    }


def request_provenance(request_id: str, scope: str, approved_by: str, approved_at: str) -> dict:
    """Record for I-22(b): the network owner asked, and a maintainer approved."""
    return {
        "path": PATH_OPERATOR_REQUEST,
        "request_id": request_id,
        "scope": scope,
        "approved_by": approved_by,
        "approved_at": approved_at,
    }


def provenance_from_corpus_source(source, observed_at=None) -> dict | None:
    """
    Recover provenance for a host replayed out of our own hit store.

    The store keeps `source` but not the index record behind it, so this is the
    weakest link in the chain and is deliberately narrow: only a source string
    that names a public index counts. `check`, `prior`, `active_probe` and
    friends describe *our* traffic, not where the host came from — re-probing on
    the strength of "we probed it before" is exactly the circular justification
    I-22 exists to break, so those return None and the caller drops the host.
    """
    # A source label proves only *which* index once nominated the host. Without
    # the stored observation time it cannot prove that nomination is still
    # fresh. Passing a missing timestamp through index_provenance() used to
    # replace it with "now", silently turning an old corpus row into standing
    # permission to probe. Missing or malformed time therefore fails closed.
    observed = parse_ts(observed_at)
    if observed is None:
        return None

    s = str(source or "").strip().lower()
    if not s:
        return None
    if s.startswith("public_index:"):
        head = s.split(":", 2)[1]
    else:
        head = s.split(":", 1)[0].split("_", 1)[0]
    if head not in PUBLIC_INDEXES:
        return None
    return index_provenance(head, None, None, "corpus_record", observed)


# ---------------------------------------------------------------------------
# Approved operator scan requests — I-22(b) / I-22a
# ---------------------------------------------------------------------------


def _scope_networks(raw_scopes) -> list:
    nets = []
    for raw in raw_scopes or []:
        try:
            net = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as e:
            raise ProvenanceUnavailable(f"unparseable request scope {raw!r}: {e}") from e
        floor = MIN_REQUEST_PREFIX4 if net.version == 4 else MIN_REQUEST_PREFIX6
        if net.prefixlen < floor:
            raise ProvenanceUnavailable(
                f"request scope {net} is wider than /{floor}; refuse rather than "
                "assume the requester speaks for all of it"
            )
        # I-11: private, reserved, loopback and link-local space is refused from
        # the checker, and an operator request is not a way around that.
        if net.is_private or net.is_loopback or net.is_link_local or net.is_reserved:
            raise ProvenanceUnavailable(f"request scope {net} is private/reserved space")
        nets.append(net)
    if not nets:
        raise ProvenanceUnavailable("approved request carries no scope")
    return nets


def load_approved_requests(path: str | None) -> dict[str, dict]:
    """
    Load the maintainer-approved scan requests manifest.

    No path means no approved requests, which is the honest default: the intake
    in I-22a is not built yet, so path (b) yields nothing rather than pretending
    to. A path that is present but malformed raises — an operator pointed us at
    an approval file and we could not read it, which is not a reason to fall
    back to trusting the candidates.

    Shape (one entry per approved request):
      {"requests": [{"request_id": "...", "approved": true,
                     "approved_by": "...", "approved_at": "2026-08-01T00:00:00Z",
                     "attested_owner": "...", "attestation": true,
                     "scope": ["203.0.113.0/24"]}]}
    """
    if not path:
        return {}
    try:
        with open(path) as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ProvenanceUnavailable(f"could not read approved requests {path!r}: {e}") from e

    rows = payload.get("requests") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ProvenanceUnavailable("approved requests file has no requests array")

    out: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ProvenanceUnavailable(f"approved request entry is not an object: {row!r}")
        rid = str(row.get("request_id") or "").strip()
        if not rid:
            raise ProvenanceUnavailable("approved request entry has no request_id")
        # I-22a: gated, not self-service. Approval and ownership attestation are
        # both required, and both are booleans we refuse to coerce — a string
        # "false" must not read as approved.
        if row.get("approved") is not True:
            raise ProvenanceUnavailable(f"request {rid} is not marked approved")
        if row.get("attestation") is not True:
            raise ProvenanceUnavailable(f"request {rid} carries no ownership attestation")
        if not str(row.get("approved_by") or "").strip():
            raise ProvenanceUnavailable(f"request {rid} names no approver")
        approved_at = parse_ts(row.get("approved_at"))
        if approved_at is None:
            raise ProvenanceUnavailable(f"request {rid} has no parseable approved_at")
        if _now() - approved_at > timedelta(days=APPROVAL_MAX_AGE_DAYS):
            raise ProvenanceUnavailable(
                f"request {rid} was approved more than {APPROVAL_MAX_AGE_DAYS} days ago; "
                "re-approve rather than replay it"
            )
        out[rid] = {
            "request_id": rid,
            "approved_by": row.get("approved_by"),
            "approved_at": approved_at.isoformat(),
            "attested_owner": row.get("attested_owner"),
            "networks": _scope_networks(row.get("scope")),
        }
    return out


def candidates_for_requests(approved: dict[str, dict], port: int, probe_path: str) -> list[dict]:
    """
    Expand approved requests into candidates.

    Only the addresses the requester actually named are enumerated, and only for
    scopes small enough to be a plausible ownership claim — this is not a way to
    turn one approval into a sweep (I-19). Anything larger than a /24 is left to
    the requester to enumerate in the request itself.
    """
    out: list[dict] = []
    for rid, req in approved.items():
        for net in req["networks"]:
            if net.version != 4 or net.prefixlen < 24:
                continue
            hosts = list(net.hosts()) or [net.network_address]
            for ip in hosts:
                out.append(
                    {
                        "ip": str(ip),
                        "port": port,
                        "stack": "operator_request",
                        "probe_path": probe_path,
                        "source": f"operator_request:{rid}",
                        "provenance": request_provenance(
                            rid, str(net), req["approved_by"], req["approved_at"]
                        ),
                    }
                )
    return out


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def verify_candidate(cand: dict, approved: dict[str, dict]) -> tuple[bool, str]:
    """Return (eligible, reason). Reason is the drop reason when not eligible."""
    try:
        ip = ipaddress.ip_address(str(cand.get("ip")))
    except ValueError:
        return False, "unparseable_address"
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False, "non_public_address"

    prov = cand.get("provenance")
    if not isinstance(prov, dict):
        return False, "no_provenance_record"

    path = prov.get("path")
    if path == PATH_PUBLIC_INDEX:
        index = str(prov.get("index") or "").strip().lower()
        if index not in PUBLIC_INDEXES:
            return False, f"index_not_recognised:{index or '?'}"
        if not prov.get("via"):
            return False, "index_record_incomplete"
        observed = parse_ts(prov.get("observed_at"))
        if observed is None:
            return False, "index_record_undated"
        age = _now() - observed
        if age.total_seconds() < -300:
            return False, "index_record_from_future"
        if age > timedelta(days=MAX_INDEX_PROVENANCE_AGE_DAYS):
            return False, "index_record_stale"
        return True, "public_index"

    if path == PATH_OPERATOR_REQUEST:
        rid = str(prov.get("request_id") or "").strip()
        req = approved.get(rid)
        if not req:
            return False, f"request_not_approved:{rid or '?'}"
        # An approval covers the space the requester attested for and nothing
        # else. Without this check one approved /24 launders a probe at any host
        # the runner happens to be holding.
        if not any(ip in net for net in req["networks"]):
            return False, f"outside_approved_scope:{rid}"
        return True, "operator_request"

    return False, f"unknown_provenance_path:{path or '?'}"


def partition_by_provenance(
    cands: list[dict], approved: dict[str, dict]
) -> tuple[list[dict], list[dict]]:
    """Split candidates into (eligible, dropped); dropped rows carry `dropped_by`."""
    eligible, dropped = [], []
    for c in cands:
        ok, reason = verify_candidate(c, approved)
        if ok:
            eligible.append(c)
        else:
            dropped.append({**c, "dropped_by": reason})
    return eligible, dropped
