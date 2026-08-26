# Roadmap

**Status date:** 2026-08-25
**Authority:** this is the current execution order. `SECURITY.md` remains the
constitution; the 2026-08-25 security review supplies the open security
requirements. Older specs and archived handoffs preserve reasoning, not current
authorization to run active traffic.

## Current operating state

| Surface | Current state |
|---|---|
| Public site and aggregate statistics | Available |
| Research lab | Available behind Cloudflare Access and the researcher allowlist |
| Local defensive CLI | Available for infrastructure the operator controls |
| Passive discovery reports and dry-run plans | Available; send no target traffic |
| Hosted `/v1/check` | Suspended; production returns `503 hosted_checks_temporarily_disabled` |
| Active discovery and ingest | Suspended; scheduled active runs were removed |
| 2026-08 discovery incident | Contained; 13 artifacts and 13 log sets deleted and verified |

Nothing on this roadmap silently widens what the project touches. Passive source
breadth, local operator-owned checks, and active third-party traffic are separate
decisions and must stay separate in code, documentation, and metrics.

---

## 0. Measurement mode — decided

This decision determines whether the large storage/control-plane project in
section 1b is necessary.

### Option A — passive and local-first (accepted 2026-08-25)

Keep internet measurement to index-derived counts and comparisons. Keep live
checks inside infrastructure the operator controls. Retire dormant active paths
that no longer serve a committed product direction.

This is the selected path. The decision and its code-retirement consequences are
recorded in
[`decisions/0001-passive-local-first.md`](decisions/0001-passive-local-first.md).

### Option B — restore governed active re-verification (not selected)

Retain the public-index provenance rule and read-only metadata probes, but rebuild
the state model before sending traffic again. Choosing this option authorizes a
design phase, not a probe run.

**What would make this step wrong:** allowing the existing dormant runner to
become the de facto decision. It remains fail-closed until the choice and its
prerequisites are explicit.

---

## 1. Security and reliability prerequisites

### 1a. Bounded hardening — do regardless of measurement mode

1. **CI and supply-chain pinning — implemented in the repository.** The
   invariant suite now runs on pushes and pull requests; GitHub Actions use
   reviewed commit SHAs and Node 24 releases; Wrangler is exact and integrity
   locked; local-lab images use registry manifest digests; and a regression test
   rejects mutable references. Dependabot proposes explicit updates. **Operator
   setting still open:** the repository has no branch protection or ruleset, so
   `CI / Invariant suite` is not yet a required status check.
2. **Isolate public statistics reads.** Materialize `/v1/stats` behind the Cache
   API and an edge rate limit so public traffic cannot exhaust the KV allowance
   used by authorization, exclusions, and retention.
3. **Tighten the public perimeter.** Put the Worker behind a controlled custom
   hostname/WAF before removing direct `workers.dev` exposure. Add enforceable
   clickjacking headers for the GitHub Pages site through a hosting layer that
   can set response headers.

These are useful whether the project remains passive or later restores active
measurement.

### 1b. Strong state model — required only before active discovery returns

Treat this as one storage/control-plane migration, not a series of KV patches:

1. **Durable pre-probe lease.** Acquire a strongly consistent per-host 14-day
   attempt lease before a packet is sent. A crash must not make a target eligible
   again.
2. **Authoritative pageable corpus.** Replace the capped `discovery:hits_index`
   array with queryable storage for host records, attempt clocks, provenance,
   deletion state, and due dates.
3. **Resumable opt-out deletion.** Purge IP/CIDR/ASN matches with persisted
   cursors, retries, verification, and a completion receipt. Attempt records must
   carry enough metadata to be purged too.
4. **Retention that scales.** Schedule records by due date; do not rely on a
   bounded sweep racing a seven-day TTL grace period.
5. **Strong security state and counters.** Move allowlist/revocation and critical
   rate limits away from eventually consistent KV. Reserve capacity for opt-outs
   and revocations ahead of telemetry.
6. **Resumable reconciliation.** Recount into versioned staging state and switch
   generations only after the entire corpus is processed.
7. **Conservative unknown-ASN handling.** Missing ASN belongs to a shared bounded
   bucket; it never skips the per-ASN safety gate.

D1, Durable Objects, or a combination are candidates. The design must be chosen
from transactional/query requirements, not from attachment to the current KV
schema.

**Exit criteria:** the re-enable tests in the security review pass under
concurrency, interruption, a corpus larger than every page limit, and a matching
record beyond the first purge page. Until then, active discovery stays off.

### 1c. Hosted checks are a separate architecture

Cloudflare Workers global `fetch` cannot reliably target IP literals, while
hostnames reintroduce DNS rebinding and CIDR/ASN opt-out ambiguity. Hosted checks
may return only behind a trusted probe service that can pin validated public
addresses, apply IP/CIDR/ASN exclusions, enforce strong rate limits, and
distinguish platform failures from clean results.

This work is not a prerequisite for the local CLI or passive research. A missing
hosted checker is not a reason to weaken target validation.

---

## 2. Close the project's open research questions

These constrain what the published numbers and any host-identifying output may
claim.

### 2a. Independent passive index — settles Q-3

Every current count is Shodan-shaped. Add Censys first and publish disagreement
between sources rather than summing them into a larger-looking population.

Use only the supported Censys Platform API and pin its requested schema version.
Keep source-specific records separate. Censys researcher terms prohibit raw data
redistribution without prior written consent, so no Censys-derived host rows may
enter a Shadowserver or other third-party handoff unless Censys grants that
consent. Aggregate research publication and third-party data transfer are
different permissions.

Global search/census access depends on the account tier or approved research
access; free Platform accounts expose lookup endpoints, not the search workflow
this item needs. If research access is requested, the maintainer must write the
application personally—Censys explicitly rejects LLM-authored applications.

Certificate Transparency and favicon lanes can follow as passive census inputs.
Index records are counts/candidates, not standing permission to probe.

**Output:** a terms-compliant API path plus source-specific counts, overlap,
disagreement, freshness, and query limitations. A single combined total is
explicitly not the deliverable.

### 2b. Disclosure routing — settles Q-2 operationally

The policy is already settled: notify before host-identifying publication, wait
90 days, and leave aggregates ungated. The delivery route is not wired.

Shadowserver's current data-sharing guidance directs prospective collaborators
to its contact form, which explicitly forbids operationally sensitive data in
the initial message. Send the reviewed, aggregate-only introduction in
[`DISCLOSURE_ENGAGEMENT.md`](DISCLOSURE_ENGAGEMENT.md), then learn whether they
want to add the fingerprints to their own scans or accept a minimized feed over
a private channel. Do not build an uploader until they specify the route and
schema.

Use national CSIRTs through FIRST, CERT/CC VINCE for multi-party cases, and
provider abuse channels as fallbacks. Do not build a home-grown mass contact
discovery or notification system.

**Output:** an accepted external route, a documented fallback, and a testable
handoff format that contains only the minimum host-identifying data required.

### 2c. Hostname handling — settles Q-1 before CT identifiers persist

CT yields organizational hostnames, a more identifying class than an address in
a hosting ASN. Before storing them, decide retention, lab visibility, deletion,
and whether any hostname-derived aggregate can be public. Default while
undecided: treat hostnames exactly like raw IPs—private and never public.

Q-4, tunnelled exposure, is a permanent measurement limitation rather than a
lane to chase. Published totals must continue to name it.

---

## 3. Threat and exposure model for AI stacks

Create a short living document mapping what an unauthenticated endpoint enables:
inference theft, model theft, execution on Ray/Jupyter, cost abuse, and pivot
potential. Separate configuration risk from version risk and name structural
blind spots.

This is mostly extraction from `worker/src/lib/exposure.js`, service findings,
and the existing limitations—not unsupported threat inflation.

---

## 4. Local-first tooling expansion

Extend `src/check_ollama_exposure.py` inside the operator's boundary:

- support the full reviewed service set, not only Ollama;
- add `--hardening-checklist` generated from observed findings;
- optionally export detection patterns for services actually detected;
- preserve ownership attestation, no redirects, URL validation, and body caps.

This is the main product-engineering track if option A remains the measurement
mode.

---

## 5. Operator hardening playbooks

Produce copy-pasteable guidance per service: bind address, authenticated reverse
proxy, non-root/read-only containers, metadata isolation, and relevant alerts.
Generate it from item 4 wherever possible so guidance stays tied to observed
findings.

Author the Kubernetes version deliberately: Service type, Ingress auth,
NetworkPolicy/Cilium, pod security, and workload identity boundaries.

---

## 6. Detection guidance — only what can be verified

Publish exactly what LeakyCompute traffic looks like in operator logs: User-Agent,
paths, method, cadence, and source-attribution limitations. Do not publish Sigma
or broader telemetry rules until they can be validated against representative
logs.

---

## 7. Shared-GPU architecture patterns

Document authenticated inference gateways, tenant isolation, metadata/network
boundaries, and safe exposure patterns only after the project has sufficient
operational evidence. This remains last because authoritative guidance without
operating experience spends credibility rather than earning it.

---

## Deliberately not on this roadmap

- **An operator-requested remote scan queue.** The local CLI covers address space
  the operator controls. The hosted checker is suspended, but its absence does
  not justify making the project originate bulk traffic for requesters.
- **Anything that proves impact.** I-3 is permanent. Report reachability; never
  send the action that demonstrates what the access permits.
- **Proxying inference through discovered hosts.** I-20, in every phase.
- **Sweeping unindexed address space.** I-19 remains a bright line even if active
  re-verification eventually returns.

## Definition of done

An item is complete only when its behavior, limits, failure mode, verification,
and documentation agree. A feature that exists in code but is disabled or not
deployed is not described as available. A partial purge, recount, census, or
notification is not described as complete.
