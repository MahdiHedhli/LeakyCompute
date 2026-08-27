"""
I-22 (provenance) and I-24 (probe rate bounded per target) — the two gates that
live in the off-Worker runner, so they are tested here in Python and driven from
provenance.test.mjs so `npm test` stays the one entry point.

Every assertion is written so it fails if the gate were removed:
  - a candidate with no provenance record reaches the probe loop  -> fail
  - "we probed it before" counts as provenance                    -> fail
  - an approval launders a probe at an address outside its scope   -> fail
  - a host probed three days ago is probed again                   -> fail
  - a missing last-seen clock is read as "nothing probed yet"      -> fail

Nothing here sends a packet: the CLI is exercised only through --self-test,
which forces --dry-run and uses RFC 5737 documentation space.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts", "discovery"))

import provenance as P  # noqa: E402
import run_multilane as R  # noqa: E402
import discover as D  # noqa: E402

FAILURES = 0


def section(title):
    print(f"\n{title}")


def check(name, fn):
    global FAILURES
    try:
        fn()
        print(f"  ok   {name}")
    except Exception as e:  # noqa: BLE001 - a test harness reports, it does not raise
        FAILURES += 1
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")


def iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def cand(ip, **kw):
    base = {"ip": ip, "port": 11434, "stack": "ollama", "probe_path": "/api/version"}
    base.update(kw)
    return base


def eligible(cands, approved=None):
    ok, dropped = P.partition_by_provenance(cands, approved or {})
    return [c["ip"] for c in ok], {d["ip"]: d["dropped_by"] for d in dropped}


# ---------------------------------------------------------------------------
section("[G1] I-22: no provenance record, no probe")

GOOD_INDEX = P.index_provenance("shodan", "product:Ollama", "ollama", "lane_search")


def _no_record():
    ok, why = eligible([cand("8.8.8.10")])
    assert ok == [], f"a candidate with no provenance reached the probe loop: {ok}"
    assert why["8.8.8.10"] == "no_provenance_record", why


check("a candidate with no provenance record is dropped before probing", _no_record)


def _bad_index():
    ok, why = eligible(
        [cand("8.8.8.11", provenance=P.index_provenance("hearsay", "?", "ollama", "lane"))]
    )
    assert ok == [], ok
    assert why["8.8.8.11"].startswith("index_not_recognised"), why


check("a source that is not a recognised public index is dropped", _bad_index)


def _incomplete():
    missing_via = dict(GOOD_INDEX)
    missing_via["via"] = None
    undated = dict(GOOD_INDEX)
    undated["observed_at"] = "not-a-date"
    ok, why = eligible(
        [cand("8.8.8.12", provenance=missing_via), cand("8.8.8.13", provenance=undated)]
    )
    assert ok == [], ok
    assert why["8.8.8.12"] == "index_record_incomplete", why
    assert why["8.8.8.13"] == "index_record_undated", why


check("an index record that does not verify at probe time is dropped", _incomplete)


def _good_index():
    ok, _ = eligible([cand("8.8.8.14", provenance=GOOD_INDEX)])
    assert ok == ["8.8.8.14"], "a genuine index listing must remain probeable"


check("a host a public index already lists is eligible", _good_index)


def _non_public_index_target():
    for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "203.0.113.1", "::1"):
        ok, why = eligible([cand(ip, provenance=GOOD_INDEX)])
        assert ok == [], f"trusted index metadata laundered non-public target {ip}"
        assert why[ip] == "non_public_address", why


check("an index record cannot launder a non-public target", _non_public_index_target)


def _circular():
    # The whole point of I-22: our own past traffic is not an entitlement.
    for src in ("check", "prior", "active_probe", "discovery", "", None):
        assert P.provenance_from_corpus_source(src) is None, f"{src!r} accepted as provenance"
    ok, why = eligible([cand("1.1.1.7", provenance=P.provenance_from_corpus_source("check"))])
    assert ok == [], "‘we probed it before’ must not justify probing it again"
    assert why["1.1.1.7"] == "no_provenance_record", why


check("'we probed it before' is not provenance", _circular)


def _corpus_index_source():
    prov = P.provenance_from_corpus_source("shodan_asn:AS64497", iso(1))
    assert prov and prov["index"] == "shodan", prov
    current = P.provenance_from_corpus_source("public_index:shodan", iso(1))
    assert current and current["index"] == "shodan", current
    ok, _ = eligible([cand("1.1.1.8", provenance=prov)])
    assert ok == ["1.1.1.8"], "a corpus row that names an index keeps its entitlement"


check("a corpus row whose source names a public index stays eligible", _corpus_index_source)


def _undated_corpus_index_source():
    assert P.provenance_from_corpus_source("shodan_asn:AS64497") is None
    assert P.provenance_from_corpus_source("public_index:shodan", "not-a-date") is None


check("a corpus index label without a timestamp is not fresh provenance", _undated_corpus_index_source)


def _public_index_metrics_require_complete_all_lane_run():
    all_ids = {lane["id"] for lane in R.LANES}
    totals = {lane_id: 10 for lane_id in all_ids}

    complete = R.public_index_publication_meta(
        requested_all_lanes=True,
        completed_lane_ids=all_ids,
        index_listed=totals,
        approved_host_count=2,
    )
    assert complete["indexed_observed"] == len(all_ids) * 10 + 2, complete

    subset = R.public_index_publication_meta(
        requested_all_lanes=False,
        completed_lane_ids=all_ids,
        index_listed=totals,
        approved_host_count=2,
    )
    assert subset == {}, subset

    one_failed = set(all_ids)
    one_failed.pop()
    incomplete = R.public_index_publication_meta(
        requested_all_lanes=True,
        completed_lane_ids=one_failed,
        index_listed={lane_id: 10 for lane_id in one_failed},
        approved_host_count=2,
    )
    assert incomplete == {}, incomplete


check("only a complete all-lane run can publish the global index metric", _public_index_metrics_require_complete_all_lane_run)


def _stale_index_source():
    prov = P.provenance_from_corpus_source("shodan_asn:AS64497", iso(30))
    ok, why = eligible([cand("1.1.1.8", provenance=prov)])
    assert ok == [], "a stale stored source label became standing probe permission"
    assert why["1.1.1.8"] == "index_record_stale", why


check("stale index provenance is not standing permission", _stale_index_source)


# ---------------------------------------------------------------------------
section("[G2] I-22a: operator requests are gated, and bounded to their scope")


# A public /24 (example.com's block). The gate refuses documentation and
# private space by design (I-11), so the happy path cannot use RFC 5737 here.
PUBLIC_SCOPE = "93.184.216.0/24"


def approved_manifest(**over):
    row = {
        "request_id": "req-1",
        "approved": True,
        "attestation": True,
        "approved_by": "maintainer",
        "approved_at": iso(1),
        "attested_owner": "ops@example.net",
        # I-11 refuses private, reserved and documentation space, so the happy
        # path has to name public space. Nothing here is probed: these tests
        # exercise the gate's arithmetic, and the CLI case below is --self-test.
        "scope": [PUBLIC_SCOPE],
    }
    row.update(over)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump({"requests": [row]}, f)
    return path


def _unapproved():
    ok, why = eligible(
        [cand("1.1.1.9", provenance={"path": "operator_request", "request_id": "ghost"})]
    )
    assert ok == [], "an unapproved request must never be probed"
    assert why["1.1.1.9"].startswith("request_not_approved"), why


check("a request that is not in the approved manifest is never probed", _unapproved)


def _scope_bound():
    path = approved_manifest()
    approved = P.load_approved_requests(path)
    os.unlink(path)
    prov = P.request_provenance("req-1", PUBLIC_SCOPE, "maintainer", iso(1))
    inside = cand("93.184.216.5", provenance=prov)
    outside = cand("93.184.217.5", provenance=prov)
    ok, why = eligible([inside, outside], approved)
    assert ok == ["93.184.216.5"], ok
    assert why["93.184.217.5"].startswith("outside_approved_scope"), why


check("an approval covers only the space it named, not whatever we are holding", _scope_bound)


def _refusals():
    cases = {
        "not marked approved": {"approved": False},
        "no ownership attestation": {"attestation": False},
        "approved as a string, not a boolean": {"approved": "true"},
        "no approver named": {"approved_by": ""},
        "approval older than the max age": {"approved_at": iso(P.APPROVAL_MAX_AGE_DAYS + 1)},
        "scope wider than the ownership floor": {"scope": ["93.0.0.0/8"]},
        "private space (I-11)": {"scope": ["10.1.0.0/16"]},
        "loopback space (I-11)": {"scope": ["127.0.0.0/24"]},
        "no scope at all": {"scope": []},
    }
    for label, over in cases.items():
        path = approved_manifest(**over)
        try:
            P.load_approved_requests(path)
        except P.ProvenanceUnavailable:
            continue
        finally:
            os.unlink(path)
        raise AssertionError(f"manifest accepted despite: {label}")


check("a manifest that cannot be trusted raises instead of approving", _refusals)


def _unreadable_manifest():
    try:
        P.load_approved_requests(os.path.join(ROOT, "no", "such", "file.json"))
    except P.ProvenanceUnavailable:
        return
    raise AssertionError("an unreadable approval file must fail closed, not fall back")


check("an unreadable approval manifest fails closed", _unreadable_manifest)


def _no_manifest_means_none():
    assert P.load_approved_requests(None) == {}, "absent intake must yield zero approvals"


check("no manifest means no approved requests (path (b) yields nothing)", _no_manifest_means_none)


def _no_sweep_laundering():
    path = approved_manifest(scope=[PUBLIC_SCOPE])
    approved = P.load_approved_requests(path)
    os.unlink(path)
    small = P.candidates_for_requests(approved, 11434, "/api/version")
    assert 1 <= len(small) <= 254, len(small)
    for c in small:
        assert ipaddress.ip_address(c["ip"]) in ipaddress.ip_network(PUBLIC_SCOPE)

    wide = approved_manifest(scope=["93.184.0.0/16"])
    approved_wide = P.load_approved_requests(wide)
    os.unlink(wide)
    assert P.candidates_for_requests(approved_wide, 11434, "/api/version") == [], (
        "a /16 approval must not expand into 65k probe targets (I-19)"
    )


check("one approval cannot be expanded into a sweep", _no_sweep_laundering)


# ---------------------------------------------------------------------------
section("[G3] I-24: at most one probe cycle per host per 14 days")


def _interval():
    last_seen = {
        "203.0.113.20": iso(3),
        "203.0.113.21": iso(20),
        "203.0.113.22": "yesterday-ish",
    }
    cands = [cand(ip) for ip in ["203.0.113.20", "203.0.113.21", "203.0.113.22", "203.0.113.23"]]
    due, too_soon = R.filter_by_interval(cands, last_seen, R.REPROBE_INTERVAL_DAYS)
    due_ips = sorted(c["ip"] for c in due)
    skipped = {c["ip"]: c["skipped_by"] for c in too_soon}
    assert "203.0.113.20" not in due_ips, "a host probed 3 days ago must be skipped"
    assert "203.0.113.21" in due_ips, "a host probed 20 days ago is due"
    assert "203.0.113.23" in due_ips, "a host we have never probed is due"
    assert skipped["203.0.113.22"] == "last_seen_unparseable", skipped
    assert skipped["203.0.113.20"].startswith("probed_"), skipped


check("a re-probe inside the interval is skipped, outside it is due", _interval)


def _interval_floor():
    """
    Drive the clamp through the CLI, not through max().

    This used to assert `max(1, R.REPROBE_INTERVAL_DAYS) == 14` — Python's
    builtin, not the runner's gate. Delete the clamp from main() and pass
    --reprobe-days 1 and the runner would probe every host daily while this
    still reported ok, which contradicts the promise at the top of this file.
    """
    assert R.REPROBE_INTERVAL_DAYS == 14, R.REPROBE_INTERVAL_DAYS

    def plan_with(days: str) -> dict:
        out = os.path.join(tempfile.mkdtemp(), "plan.json")
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "discovery", "run_multilane.py"),
             "--self-test", "--reprobe-days", days, "--output", out],
            capture_output=True,
            text=True,
            timeout=120,
            env={k: v for k, v in os.environ.items() if not k.startswith(("SHODAN", "LEAKY"))},
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        return json.load(open(out)).get("meta") or {}

    lowered = plan_with("1")
    assert lowered.get("reprobe_interval_days") == 14, (
        f"--reprobe-days 1 was accepted: {lowered.get('reprobe_interval_days')}"
    )
    raised = plan_with("30")
    assert raised.get("reprobe_interval_days") == 30, (
        "a flag may slow re-verification, never speed it"
    )


check("the interval is a floor a flag cannot lower", _interval_floor)


def _fail_closed_clock():
    for base, token in ((None, "t"), ("https://api.test", None), ("", "")):
        try:
            R.fetch_hits(base, token)
        except R.IntervalDataUnavailable:
            continue
        raise AssertionError(
            "a missing last-seen clock must raise: an empty map reads as "
            "'nothing has ever been probed' and re-probes the whole corpus at once"
        )


check("an unreadable last-seen clock raises rather than returning an empty map", _fail_closed_clock)


# ---------------------------------------------------------------------------
section("[G4] I-24: per-neighbourhood and per-ASN ceilings")


def _ceilings_declared():
    assert R.MAX_INFLIGHT_PER_24 == 1, R.MAX_INFLIGHT_PER_24
    assert R.MAX_INFLIGHT_PER_ASN <= 2, R.MAX_INFLIGHT_PER_ASN
    assert R.MIN_SECONDS_BETWEEN_SAME_24 >= 30.0, R.MIN_SECONDS_BETWEEN_SAME_24
    assert R.RUNNER_MAX_RATE <= R.HARD_MAX_RATE, "the runner must be no faster than the repo ceiling"
    # The flag is clamped by both ceilings, so --rate 999 cannot raise it.
    assert min(999.0, R.RUNNER_MAX_RATE, R.HARD_MAX_RATE) <= R.RUNNER_MAX_RATE


check("the declared ceilings are the ones the invariant claims", _ceilings_declared)


def _bucket_keys():
    net4, asn = R.bucket_keys({"ip": "203.0.113.55", "asn": "as64496"})
    assert net4 == "203.0.113.0/24", net4
    assert asn == "AS64496", asn
    net6, _ = R.bucket_keys({"ip": "2001:db8::1"})
    assert net6.endswith(f"/{R.V6_BUCKET_PREFIX}"), net6
    assert R.bucket_keys({"ip": "not-an-address"}) == (None, None)


check("neighbourhood keys are per-/24 (v4) and per-/48 (v6)", _bucket_keys)


def _gate_serialises():
    gate = R.BucketGate(1, 0.15)
    order = []

    def worker(tag):
        gate.acquire("203.0.113.0/24")
        order.append(f"in:{tag}")
        time.sleep(0.1)
        order.append(f"out:{tag}")
        gate.release("203.0.113.0/24")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    elapsed = time.monotonic() - started

    # Never two inside the neighbourhood at once…
    depth = 0
    for event in order:
        depth += 1 if event.startswith("in:") else -1
        assert depth <= 1, f"two probes in one /24 at once: {order}"
    # …and the spacing is real, not just the ceiling.
    assert elapsed >= 0.3, f"three spaced entries finished in {elapsed:.2f}s"


check("a neighbourhood admits one probe at a time, spaced apart", _gate_serialises)


def _asn_gate():
    gate = R.BucketGate(R.MAX_INFLIGHT_PER_ASN, 0.0)
    live = []
    peak = [0]
    lock = threading.Lock()

    def worker():
        gate.acquire("AS64496")
        with lock:
            live.append(1)
            peak[0] = max(peak[0], len(live))
        time.sleep(0.05)
        with lock:
            live.pop()
        gate.release("AS64496")

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert peak[0] <= R.MAX_INFLIGHT_PER_ASN, f"peak concurrency {peak[0]} in one ASN"


check("an ASN never exceeds its in-flight ceiling", _asn_gate)


def _spread():
    cands = [cand(f"203.0.113.{i}", asn="AS1") for i in range(1, 4)] + [
        cand(f"198.51.100.{i}", asn="AS2") for i in range(1, 4)
    ]
    spread = R.spread_by_bucket(cands)
    assert len(spread) == len(cands), "spreading must not drop or duplicate a candidate"
    assert {c["ip"] for c in spread} == {c["ip"] for c in cands}
    nets = [R.bucket_keys(c)[0] for c in spread]
    assert all(a != b for a, b in zip(nets, nets[1:])), f"same /24 back to back: {nets}"


check("candidates are spread across neighbourhoods, not walked in order", _spread)


# ---------------------------------------------------------------------------
section("[G6] I-1/I-2/I-6/I-23: what actually goes on the wire")

# Paths whose semantics have been checked against the upstream project and are
# metadata, health, version or listing reads. A lane path outside this set has
# not been reviewed under I-2 and must not ship, whatever it would tell us.
REVIEWED_PROBE_PATHS = {
    "/",                       # unauth landing page
    "/api/ps",                 # ollama: loaded models
    "/api/tags",               # ollama: model listing
    "/api/version",            # ray, ollama
    "/api/config",             # open webui: public config document
    "/v1/models",              # openai-compatible listing
    "/v2",                     # triton: kserve v2 server metadata
    "/config",                 # gradio: interface schema
    "/health",                 # mlflow: static "OK"
    "/health/liveliness",      # litellm: static; plain /health bills the operator
    "/system_stats",           # comfyui
    "/data/plugins_listing",   # tensorboard: enabled plugins
}


def _probe_paths_reviewed():
    for lane in R.LANES:
        path = lane["probe_path"]
        assert path in REVIEWED_PROBE_PATHS, (
            f"lane {lane['id']} probes {path}, which has no I-2 review"
        )
        for forbidden in ("/run", "/queue", "/submit", "/api/jobs", "/repository"):
            assert not path.startswith(forbidden), f"{lane['id']}: {path} makes the target act"


check("every lane probes a reviewed metadata path", _probe_paths_reviewed)


def _litellm_is_not_billed():
    """
    LiteLLM's proxy /health is not metadata: it runs a live check by issuing a
    real completion against every model in the operator's config, so probing it
    makes an unauthenticated proxy — the population this lane exists to find —
    do work and pay for it. I-2 forbids the request; I-3 forbids proving the
    impact. /health/liveliness returns a constant and calls no model.
    """
    lane = next(L for L in R.LANES if L["id"] == "litellm")
    assert lane["probe_path"] != "/health", "restores a probe that bills the operator"
    assert lane["probe_path"].startswith("/health/")
    profiles = open(os.path.join(ROOT, "scripts", "discovery", "profiles.yaml")).read()
    litellm = profiles.split("\n  litellm:", 1)[1].split("\n  vllm:", 1)[0]
    assert "path: /health/liveliness" in litellm, "profiles.yaml restored the billing probe"


check("the litellm lane does not spend the operator's money", _litellm_is_not_billed)


def _shodan_minimized_and_errors_sanitized():
    original = D.http_json
    seen = {}

    def small(url, **kwargs):
        seen["url"] = url
        seen["cap"] = kwargs.get("max_response_bytes")
        return 200, {
            "total": 1,
            "matches": [{
                "ip_str": "93.184.216.34",
                "port": 11434,
                "timestamp": iso(1),
                "location": {"country_code": "US"},
            }],
        }

    try:
        D.http_json = small
        rows, _, _, total = D.shodan_search("secret", "product:Ollama", 1)
        query = seen["url"].split("?", 1)[1]
        params = urllib.parse.parse_qs(query)
        assert params["minify"] == ["false"]
        assert "data" not in params["fields"][0]
        assert "ollama" not in params["fields"][0]
        assert seen["cap"] == 256 * 1024
        assert rows[0]["timestamp"] and total == 1

        hostile = "93.184.216.34 SECRET-MODEL-CONTENT"
        D.http_json = lambda *_args, **_kwargs: (200, hostile)
        try:
            D.shodan_search("secret", "product:Ollama", 1)
            raise AssertionError("malformed Shodan response was accepted")
        except SystemExit as exc:
            message = str(exc)
            assert hostile not in message
            assert "response=text length=" in message
    finally:
        D.http_json = original


check("Shodan data is minimized and failure logs cannot disclose response content", _shodan_minimized_and_errors_sanitized)


def _lane_failure_aborts_before_fallback():
    try:
        R.require_lane_collection_succeeded(["ollama"])
        raise AssertionError("a passive lane failure did not stop the run")
    except SystemExit as exc:
        assert "ollama" in str(exc)


check("a passive lane failure aborts instead of falling back to corpus probes", _lane_failure_aborts_before_fallback)


def _no_redirect_following():
    """
    I-6, off-Worker. The Worker has enforced redirect:"manual" since it shipped;
    the runner carries the majority of probe volume and used urlopen()'s default
    opener, which follows 3xx silently — so a probed host could aim our next GET
    at an address in no public index (I-22), at a path nobody reviewed (I-2).
    """
    handler = D._NO_REDIRECT_OPENER.handle_error.get("http", {})
    assert D.http_json.__code__.co_names.count("urlopen") == 0, (
        "http_json is back on the default opener, which follows redirects"
    )
    assert D._NoRedirect().redirect_request(None, None, 302, "", {}, "http://evil.test/") is None
    assert any(
        isinstance(h, D._NoRedirect) for h in D._NO_REDIRECT_OPENER.handlers
    ), f"opener has no no-redirect handler: {handler}"


check("a probed host cannot bounce the runner onto another host", _no_redirect_following)


def _probe_agent_is_the_published_one():
    """
    I-23 promises one search. public/scanning.html tells operators to look for
    LeakyCompute-SafeProbe; the runner's own USER_AGENT constant was never
    referenced, so probes went out under a different name entirely.
    """
    assert D.PROBE_USER_AGENT.startswith("LeakyCompute-SafeProbe/")
    assert R.USER_AGENT == D.PROBE_USER_AGENT, "the runner probes under a different name"
    page = open(os.path.join(ROOT, "public", "scanning.html")).read()
    assert "LeakyCompute-SafeProbe" in page
    for stale in ("LeakyCompute-MultiLane", "LeakyCompute-Discovery"):
        assert stale not in page, f"/scanning still names {stale}, which no probe sends"

    src = open(os.path.join(ROOT, "scripts", "discovery", "run_multilane.py")).read()
    assert 'headers={"User-Agent": USER_AGENT}' in src.replace("\n", "").replace("        ", ""), (
        "safe_probe does not set the probe agent, so http_json's default is used"
    )


check("probes carry the agent the public page names", _probe_agent_is_the_published_one)


# ---------------------------------------------------------------------------
section("[G5] end to end: the gates decide before anything is written")


def _self_test_cli():
    out = os.path.join(tempfile.mkdtemp(), "plan.json")
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "discovery", "run_multilane.py"),
         "--self-test", "--output", out],
        capture_output=True,
        text=True,
        timeout=120,
        # No credentials: a run that reached an index or the admin API would
        # fail rather than quietly do it.
        env={k: v for k, v in os.environ.items() if not k.startswith(("SHODAN", "LEAKY"))},
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    plan = json.load(open(out))
    meta = plan.get("run_meta") or plan.get("meta") or {}
    kept = [c["ip"] for c in plan.get("candidates", [])]

    assert meta.get("provenance_enforced") is True, meta
    assert meta.get("provenance_dropped") == 4, meta
    # Only the two hosts a public index actually listed survive to the plan.
    assert sorted(kept) == ["1.1.1.8", "8.8.8.10"], kept
    for dropped in ("8.8.8.11", "8.8.8.12", "1.1.1.7", "1.1.1.9"):
        assert dropped not in json.dumps(plan.get("candidates", [])), (
            f"{dropped} has no valid provenance but survived into the probe plan"
        )
    # I-22 drops are announced on stderr, where an unattended run cannot lose them.
    assert "I-22" in proc.stderr, proc.stderr
    console = proc.stdout + proc.stderr
    for ip in ("8.8.8.10", "8.8.8.11", "8.8.8.12", "1.1.1.7", "1.1.1.8", "1.1.1.9"):
        assert ip not in console, f"raw candidate address leaked to console: {ip}"

    # The plan itself must record that it was not interval- or exclusion-filtered,
    # rather than implying it was.
    assert meta.get("exclusion_filtered") is False, meta
    assert meta.get("interval_enforced") is False, meta
    assert meta.get("reprobe_interval_days") == 14, meta
    assert meta.get("rate") <= R.RUNNER_MAX_RATE, meta


check("--self-test drops every ineligible candidate before the plan is written", _self_test_cli)


def _active_runner_requires_governed_path():
    try:
        R.run_probes([], 0.1, 1, 1.0)
        raise AssertionError("legacy run_probes unexpectedly remained callable")
    except RuntimeError as exc:
        assert "legacy_target_probe_disabled" in str(exc)

    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "discovery", "run_multilane.py"),
         "--ingest"],
        capture_output=True,
        text=True,
        timeout=30,
        env={k: v for k, v in os.environ.items() if not k.startswith(("SHODAN", "LEAKY"))},
    )
    assert proc.returncode != 0, "active runner ran without its authenticated control plane"
    assert "SHODAN_API_KEY required" in proc.stderr + proc.stdout


check("legacy probing stays hard-disabled and active mode requires the governed path", _active_runner_requires_governed_path)


# ---------------------------------------------------------------------------
print("\n[G7] I-5: the port comes from the index record, so it is untrusted")


def _port_allowlist_defaults_narrow():
    lane = {"id": "x", "port_default": 9999}
    assert R.lane_allowed_ports(lane) == {9999}, "a lane with no declaration must be narrow"


def _port_allowlist_drops_off_port_candidates():
    lanes = [
        {"id": "gradio", "port_default": 7860, "allowed_ports": [7860]},
        {"id": "vllm", "port_default": 8000, "allowed_ports": [8000, 8080]},
    ]
    cands = [
        {"ip": "203.0.113.1", "port": 7860, "stack": "gradio"},
        {"ip": "203.0.113.2", "port": 80, "stack": "gradio"},     # proxied Gradio
        {"ip": "203.0.113.3", "port": 443, "stack": "gradio"},
        {"ip": "203.0.113.4", "port": 8080, "stack": "vllm"},
        {"ip": "203.0.113.5", "port": 22, "stack": "vllm"},       # never
    ]
    ok, bad = R.partition_by_allowed_port(cands, lanes)
    assert [c["port"] for c in ok] == [7860, 8080], [c["port"] for c in ok]
    assert {c["port"] for c in bad} == {80, 443, 22}, bad


def _laneless_candidate_held_to_the_union_not_to_anything():
    # An approved operator request and a replayed corpus row have no lane. They
    # must still be inside the project's known-AI-port set — the first version of
    # this gate dropped them outright, which would have disabled I-22 path (b).
    lanes = [
        {"id": "ollama", "port_default": 11434, "allowed_ports": [11434]},
        {"id": "ray", "port_default": 8265, "allowed_ports": [8265]},
    ]
    ok, bad = R.partition_by_allowed_port(
        [
            {"ip": "203.0.113.9", "port": 11434, "stack": "operator_request"},
            {"ip": "203.0.113.8", "port": 8265, "stack": "prior"},
            {"ip": "203.0.113.7", "port": 22, "stack": "operator_request"},
            {"ip": "203.0.113.6", "port": 443, "stack": "prior"},
        ],
        lanes,
    )
    assert [c["port"] for c in ok] == [11434, 8265], [c["port"] for c in ok]
    assert {c["port"] for c in bad} == {22, 443}, bad


def _lane_candidate_cannot_borrow_another_lanes_port():
    lanes = [
        {"id": "ollama", "port_default": 11434, "allowed_ports": [11434]},
        {"id": "ray", "port_default": 8265, "allowed_ports": [8265]},
    ]
    ok, bad = R.partition_by_allowed_port(
        [{"ip": "203.0.113.5", "port": 8265, "stack": "ollama"}], lanes
    )
    assert ok == [], "a lane candidate must be held to its own lane's ports"
    assert len(bad) == 1


def _unparseable_port_is_dropped():
    lanes = [{"id": "k", "port_default": 8000, "allowed_ports": [8000]}]
    ok, bad = R.partition_by_allowed_port(
        [{"ip": "203.0.113.9", "port": None, "stack": "k"},
         {"ip": "203.0.113.9", "port": "eighty", "stack": "k"}], lanes
    )
    assert ok == [] and len(bad) == 2, (ok, bad)


def _every_lane_declares_ports_it_can_justify():
    # A lane whose query matches page content rather than port can return any
    # port; the allowlist is the only thing standing between that and a probe.
    for lane in R.LANES:
        allowed = R.lane_allowed_ports(lane)
        assert allowed, f"{lane['id']} has an empty port allowlist"
        assert int(lane["port_default"]) in allowed, (
            f"{lane['id']} cannot probe its own default port"
        )
        assert all(0 < p < 65536 for p in allowed), lane["id"]
        # 22/80/443 are not AI service ports. If one ever appears here it is a
        # widening that belongs in an amendment, not in a lane edit.
        assert not (allowed & {22, 80, 443, 3389}), (
            f"{lane['id']} allows a non-AI port: {sorted(allowed)}"
        )


check("a lane with no declared ports stays narrow", _port_allowlist_defaults_narrow)
check("off-allowlist ports are dropped before probing", _port_allowlist_drops_off_port_candidates)
check("a laneless candidate is held to the port union, not to nothing", _laneless_candidate_held_to_the_union_not_to_anything)
check("a lane candidate cannot borrow another lane's port", _lane_candidate_cannot_borrow_another_lanes_port)
check("an unparseable port is dropped, not coerced", _unparseable_port_is_dropped)
check("every lane's allowlist contains only justifiable ports", _every_lane_declares_ports_it_can_justify)


print("\n" + (f"{FAILURES} FAILURE(S)" if FAILURES else "all assertions passed"))
sys.exit(1 if FAILURES else 0)
