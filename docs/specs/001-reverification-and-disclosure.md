# Spec: re-verification corpus + coordinated disclosure

**Status:** draft · **Date:** 2026-08-10

> Amends I-18. Adds I-22…I-27. Settles Q-2. Supersedes the fixed `max_hosts`
> volume cap with a provenance rule plus behavioural discipline.

## Problem

The public page shows an archive-era research snapshot (19,348 hosts) beside a
live instrumented count (168). Presented side by side with equal weight, the
pair implies a claim we have not measured and do not believe: that exposure
collapsed by two orders of magnitude since the archive. A reader's most natural
inference — "this problem largely fixed itself" — is the opposite of what the
evidence supports, and we are publishing it by layout.

The live number is small because `search_limit` and `max_hosts` are set equal in
every lane, so passive breadth is throttled to the active re-verification budget
(25–48 hosts per lane). The cap was chosen as a proxy for restraint. It is a
poor proxy: it limits how much we can honestly say without limiting any of the
behaviours that would actually make us indistinguishable from the tooling we
study.

Separately, we can identify exposed hosts but have no way to tell their
operators (Q-2). Every host added to the corpus today is one more operator we
have decided not to help.

## Constitution check

| Question | Answer |
|---|---|
| Which invariants could this break? | **I-18** (amended below). I-1, I-2, I-5, I-6, I-7 unchanged and still binding. I-19 unchanged — we still never sweep address space. |
| Every new request a read-only GET to a metadata endpoint? (I-1, I-2) | Yes. This spec changes **how many** hosts are probed and **which** are eligible. It adds no path, method, or payload. The tier-1 probe table is untouched. |
| Widens the port allowlist? (I-5) | No. |
| Introduces a new class of identifier? (I-14, Q-1) | No new class. Volume of existing classes (IP, ASN, country) increases; retention and minimisation tighten correspondingly (I-26). Hostnames remain out of scope pending Q-1. |
| Increases active probe volume? What is the cap? (I-18) | Yes, materially. The fixed per-lane cap is replaced by a rate ceiling plus a re-probe interval (I-24). Volume becomes a function of how much a public index already lists, not of how hard we look. |
| Indistinguishable from NadMesh on the wire? (§0) | No, and this is the load-bearing answer. NadMesh **discovers by probing**: it sweeps address space and learns what is there. Under I-22 we probe **only hosts a public index already lists**, so our traffic can never be the thing that finds a host. That difference is visible in a packet capture (no sweep, no unlisted destination) and auditable from the source tree (every target traces to an index record). |

Open questions this depends on: **Q-2**, which the template forbids shipping
around. It is settled in *Disclosure* below and promoted to I-27. **Q-3**
(source bias) is not settled and constrains what we may claim; see *Limitations*.

## Proposal

### 1. Amend I-18

> **I-18 (amended). The Worker does not scan the internet.** One target per
> request, on request. Bulk re-verification runs off-Worker, rate-limited, and
> only against hosts already listed in a public index (I-22).

The words "slowly, capped" are replaced by the specific governance in I-22–I-26.
A fixed total was never the control that mattered.

### 2. New invariants

**I-22. We never discover a host by probing.** Every active probe target must be
eligible under exactly one of:

- **(a) Already indexed.** The host already appears in a public index (Shodan,
  Censys, or an equivalent OSINT source used within its terms). Our traffic
  reveals nothing that was not already published.
- **(b) Operator-requested.** The network owner asked us to scan it, through the
  rate-limited request template in this repository's issues.

If a host is eligible under neither, we do not touch it. This is the bright line
that replaces the volume cap: we only ever look at hosts someone else already
published, or hosts whose owner asked us to look.

**I-22a. Path (b) is gated, not self-service.** An unverified request form is a
way to make this project scan a stranger, so a request is never auto-actioned.
Every submission carries the same ownership attestation the public checker
requires (I-10), is refused for private and reserved ranges (I-11), is
rate-limited per requester and globally, and requires maintainer approval before
the first probe — the same approve/revoke Action pattern that already gates lab
access. Refusals are logged for abuse review. A requester may only attest for
address space they control; requests naming third-party space are refused and
logged, not silently dropped.

**I-23. Our probes are attributable.** A single identifiable User-Agent
(`LeakyCompute-SafeProbe/*`), forward-and-reverse-confirmed PTR on every source
address, and a public page at `/scanning` explaining who we are, what we send,
and how to opt out. An operator who sees us in their logs must be able to find
out what we are in one search.

**I-24. Probe rate is bounded per target, not per run.** At most one probe cycle
per host per 14 days; per-/24 and per-ASN concurrency ceilings; global rate
ceiling enforced in the runner. Re-verification is a slow background process,
never a burst.

**I-25. Opt-out is honoured before the probe, not after.** An exclusion list
(IP, CIDR, or ASN) is consulted before any request is emitted. Exclusions never
expire, and no justification is required.

The intake is `.github/ISSUE_TEMPLATE/request_removal.yml`, with an email route
for operators who will not open a GitHub account — needing an account to be left
alone is not an opt-out. Exclusion deletes existing records as well as stopping
future probes.

**The verification asymmetry is deliberate and runs opposite to I-22a.** A
*scanning* request is actioned only after approval, because a bad-faith one aims
our traffic at a stranger. A *removal* request is actioned on receipt and
reviewed afterwards, because the worst case of a bad-faith one is that we fail
to probe a host we were never entitled to probe. Where the two conflict —
someone requests a scan of space another party has excluded — the exclusion
wins, with no appeal path.

**I-26. Corpus records are minimised and expire on silence.** Per host we retain:
address, port, service, version string, first/last seen, geo/ASN. We do not
retain model lists, job records, page bodies, or any content beyond what the
finding requires.

A record is deleted 180 days after its **last successful probe**. A host that
answers resets the clock, so a live exposure stays tracked for as long as it
stays exposed; a host that has gone quiet — remediated, re-addressed, or
decommissioned — ages out and is deleted, not archived. Expiry is measured from
last contact, never from record creation.

**I-27. We notify before we publish.** Settles Q-2 — see *Disclosure*.

### 3. Decouple the caps

`search_limit` (passive pull from an index — no packets to third parties) and
`max_hosts` (active read-only re-verification) become independent. Passive pull
is bounded by API quota and I-21. Active re-verification is bounded by I-24.

### 4. Never blend counted with re-verified

Three numbers, never summed, each with its own provenance string:

```json
{
  "archive_snapshot": { "hosts": 19348, "as_of": "2024-xx", "source": "filtered STOLEN COMPUTE catalog" },
  "indexed_observed": { "hosts": 0, "source": "public index records, counted not probed" },
  "reverified":       { "hosts": 0, "window_days": 180, "source": "read-only GET by us" }
}
```

### 5. The re-verification cohort — the number that answers the actual question

Draw a random sample from the 19,348 archive hosts and re-verify it under
I-22–I-26. This yields the claim the current layout is gesturing at but has not
earned:

> Of *N* hosts listed as exposed in the archive-era catalog, *X%* still answer
> an unauthenticated read today.

That is a measured answer to "did this get better?", it is defensible, it is
novel, and it is a far stronger result than a larger raw count. It also
retroactively fixes the misleading juxtaposition: the archive number stops being
a scoreboard and becomes a cohort with a follow-up.

## Disclosure — settling Q-2

Q-2 currently reads "until there is a policy, we do not contact operators."
Replace with I-27:

> **I-27. We notify before we publish.** No host-identifying finding is
> published, shared, or shown in the lab before a notification attempt has been
> made through the routes below and the disclosure window has elapsed.

**Routes, in order of preference:**

1. **The Shadowserver Foundation.** Purpose-built for exactly this: they run
   free daily notification to network owners and national CSIRTs worldwide and
   accept data from external researchers. This is the highest-leverage option by
   a wide margin — it solves per-operator contact discovery, which is the part
   we cannot do ourselves at any scale. *Confirm their current researcher intake
   process and data-format requirements before building to it.*
2. **National CSIRTs**, routed by the country data we already hold, via the
   FIRST member directory. Appropriate for country-concentrated clusters.
3. **CERT/CC (VINCE)** for the multi-party case — many affected operators, no
   single vendor. This is the classic shape for a class of misconfiguration
   rather than a product flaw.
4. **RDAP/whois abuse contacts and cloud-provider researcher channels.** A large
   share of these hosts will sit in a handful of providers; provider-level
   notification reaches more operators per message than host-level does.
5. **Upstream vendors** — Ollama, Ray, Jupyter — for secure-default advocacy.
   This is the only route that reduces the population rather than the count, and
   it is the one worth the most long term.

**Window:** 90 days from first notification attempt to publication of any
host-identifying detail. Aggregates (country, ASN, stack, version) are not
host-identifying and are not gated by the window.

## Sequencing

The order is load-bearing, not administrative. Expanded probing must not ship
before the machinery that lets people escape it.

1. **DONE — opt-out intake live.** Removal template, honour-on-receipt Action,
   `/v1/admin/exclusions`, runner filtering that **fails closed** when the list
   cannot be read, auto-honour bound against griefing, and tests asserting the
   probe is *skipped* rather than suppressed. I-25 is machine-checked.
2. **DONE — `/scanning` page live** (I-23). An operator who finds us in their
   logs can identify us and leave in one click, before volume increases.
3. **DONE — I-24/I-26 governance.** Global rate ceiling plus per-/24 and per-ASN
   in-flight ceilings and spacing; one probe cycle per host per 14 days, failing
   closed without last-seen data; retention expiring from last successful probe,
   swept on cron rather than on intention. The interval clock reads the probe
   *attempt* ledger, not the hit store — the hit store holds only hosts that
   answered, so a host since firewalled left no trace there and was being
   re-probed every run.
4. **DONE and MEASURED** (dry run, 2026-08-17, zero packets to any target).
   `search_limit` is decoupled from `max_hosts` across 14 lanes, and the split is
   behaving as intended: **1,537 hosts observed in public index records**
   (counted, not probed) against **370 probe-eligible** after `max_hosts` caps.
   107 distinct ASNs; concentration DE 79 / US 66 / CN 50 / FR 33.

   The number that matters for the counter problem: 1,537 observed is **~8% of
   the 19,348 archive figure**, and Shodan's own reported totals per lane exceed
   what we pulled, so supply is bounded by `search_limit` rather than exhausted.
   Even so, no plausible breadth increase closes a 19,348 gap — which is the
   quantitative case for step 5 rather than for raising caps again.

   Two lanes returned zero and need query work before they count as coverage:
   `triton` (`port:8000 "Triton Inference Server"`) and `gradio`. `vllm` returned
   13 against a cap of 30.
5. **Archive re-verification cohort** — not started. Still the highest-value
   output in this spec.
6. **Disclosure routing** (I-27) — not started. The lab already withholds the
   address of an unnotified host until the window elapses, so the *mechanism*
   exists; the routing does not. Gated on Shadowserver intake confirmation.

I-22 (provenance) **is enforced in code** as of the governance commit. Every
candidate carries a record naming a recognised public index or an approved
operator request, and a row whose only provenance is our own prior traffic is
refused — "we probed it before" is not an entitlement. Verified by
`governance_gates.py`, which runs under `npm test` via `provenance.test.mjs`.

Still open against this section:

- **I-22a has no intake.** Operator scan requests are a maintainer-curated JSON
  manifest passed with `--approved-requests`. Without that flag, zero candidates
  are eligible by that path. The gate is real; the front door is unbuilt, so the
  issue template, requester rate limit, and refusal log described in I-22a do not
  exist yet.
- **Provenance is not persisted.** The corpus stores `source`, so a replayed
  row's entitlement is re-derived from a string rather than read from a record.
  A worker-side provenance field would make it auditable after the fact.
- **No real run has occurred.** Steps 1–4 are all enforcement. Nothing has been
  measured, and until the Worker is deployed a real `--ingest` run cannot even
  start: the exclusion and interval gates fail closed against endpoints that
  exist only in the undeployed code.

Steps 1–3 were the cost of step 4. Shipping 4 first would have been the version
of this project that its own §0 warns about.

## Out of scope

- Any sweep of address space to discover hosts not already indexed (I-19).
- Any non-GET request, new probe path, or new port (I-1, I-2, I-5).
- Any demonstration of impact against a third party (I-3), including for the
  write-up, including with a bigger corpus behind it.
- Hostname-derived identifiers, pending Q-1.
- Direct operator contact by us at scale before route 1 or 2 is in place —
  self-run notification without an established channel is how research projects
  get classified as the threat.

## Verification

New tests required before this ships:

| Invariant | Test |
|---|---|
| I-22 | Probe target traceable to neither an index record nor an approved request → runner refuses; assert on a synthetic target |
| I-22a | Unapproved request is never probed; request naming third-party space is refused and logged; private ranges refused (I-11) |
| I-24 | Re-probe inside 14 days is skipped; per-ASN ceiling enforced |
| I-25 | Exclusion consulted before the first request is emitted, not after; exclusion beats an approved scan request for the same space |
| I-26 | Retained record contains no model list / job record / body; expiry measured from last **successful** probe, and a successful probe resets it |
| I-27 | Host-identifying field is withheld from the public payload before window elapse |

I-23 is process, not code, except the User-Agent constant — assert that.
I-27's window logic is machine-checkable; the notification *attempt* is not.
Say so in §4a rather than implying coverage we do not have.

## Limitations

What a reader could wrongly conclude, and what the UI must say:

- **"Re-verified count is the population."** It is not. It is bounded by what
  public indexes list, which inherits their bias (Q-3, unsettled). Tunnelled
  exposure remains structurally invisible (Q-4). The re-verified card must carry
  both caveats.
- **"The archive→cohort delta is the internet-wide trend."** It is a trend for
  one archive-era cohort, with survivorship effects — hosts may have moved,
  re-addressed, or gone behind CGNAT rather than been secured. State the
  confidence interval and the ambiguity explicitly.
- **"Clean means safe."** Unchanged from I-8, and more important at scale.
