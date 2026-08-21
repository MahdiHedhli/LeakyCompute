# Roadmap

Ordered by what closes a question this project has already admitted is open,
then by value per hour of work. Items are described with the reason they matter
and the thing that would make them wrong, because a roadmap that only lists
features is a wishlist.

Two notes on how to read it:

- **Nothing here widens what we probe.** Every item is about making the
  measurement more useful or more honest. Expanding the *sources* we read is
  planned (item 0b); expanding what we *touch* is not.
- **Content is not free.** Five of these produce documents rather than code, and
  a wrong hardening recommendation is worse than none. Where a document can be
  generated from something the tool actually observed, it should be.

---

## 0. Closing our own open questions

These outrank everything below because `SECURITY.md` §6 already names them as
unsettled, and unsettled questions constrain what the published numbers may
claim.

### 0a. Disclosure routing — settles Q-2

The policy is written (I-27: notify before host-identifying publication, 90-day
window, aggregates ungated). The routing is not wired. We can identify hundreds
of exposed hosts and cannot tell their operators, and notifying at scale
ourselves is how a research project gets reclassified as the threat.

Route is the Shadowserver Foundation, who already run free daily notification to
network owners and national CSIRTs. Below that: national CSIRTs via the FIRST
directory routed on the country data we hold, CERT/CC's VINCE for the
multi-party case, and provider abuse channels — which reach more operators per
message than host-level contact ever will.

**Blocked on:** confirming Shadowserver's current researcher intake and format.

**What would make it wrong:** building our own notification pipeline instead.
Contact discovery at scale is the part we cannot do responsibly, and it is
exactly what they already do.

### 0b. A second index — settles Q-3

Every number we publish is Shodan-shaped, and our own limitations say so. Censys
first (free tier, genuinely independent), then certificate transparency and
favicon-hash lanes.

This does not widen probing: index records are counted, never probed, unless a
candidate passes all four gates like any other.

**What would make it wrong:** treating a second source as more coverage rather
than as a cross-check. The point is to find out where Shodan is blind, which
means publishing the disagreement, not summing the two.

---

## 1. Threat and exposure model for AI stacks

A short living document mapping what an unauthenticated endpoint actually
enables — inference theft, model theft, RCE on Ray and Jupyter, cost abuse,
pivot potential — which services carry *configuration* risk versus *version*
risk, and where the measurement is structurally blind.

Mostly **extraction, not authorship**. The four exposure classes already exist in
`worker/src/lib/exposure.js` with the prose explaining each. Configuration-versus-
version is already encoded: Ray is flagged on configuration precisely because
CVE-2023-48022 is disputed and no upgrade closes it, and the CVE line carries its
own denominator because only a minority of hosts disclose a version. The blind
spots are Q-3 and Q-4.

Highest value per hour on this list, and the piece a security engineer at a GPU
provider could hand to a customer.

## 2. Local-first tooling expansion

`src/check_ollama_exposure.py` already runs inside an operator's boundary and
already forces an ownership attestation. Extend it:

- the full lane set, not just Ollama
- a `--hardening-checklist` mode that emits a prioritised list from what it found
- optional export of detection patterns for the services it detects

This is the only substantial engineering item here, and it is what makes item 3
sustainable: a checklist generated from observed findings is a formatter, where a
hand-maintained guide per service is a permanent content debt.

## 3. Operator hardening playbooks

Copy-pasteable guides per service — bind address, authenticating reverse proxy
patterns, non-root and read-only rootfs, no route to cloud metadata, alerting on
the endpoints that matter. Linked from findings so the output moves from "you are
exposed" to "here is how to close it in your environment."

**Generated from item 2 wherever possible.** Written by hand this is five-plus
services and ongoing accuracy maintenance, and an incorrect hardening
recommendation does more harm than silence.

The exception worth authoring directly is the **Kubernetes-flavoured** version —
NetworkPolicy and Cilium, Service type, Ingress auth, pod security standards.
That is not in our remediation strings today and it is the shape most relevant to
anyone running inference on shared GPU infrastructure.

## 4. Detection guidance — only the part we can verify

We measure from outside; detection is an inside-the-host discipline. Sigma rules
we cannot test against real telemetry would be speculation formatted as guidance,
which is the one thing this project has never done.

The defensible slice, and the one to publish: **exactly what our probe looks like
in your logs** — the User-Agent, the paths, the cadence. First-party,
verifiable, and already half-written on `/scanning`.

Broader alerting guidance waits until we have telemetry to validate it against.

## 5. Architecture patterns for inference on shared GPU infrastructure

Patterns for exposing inference only through authenticated gateways, isolation
expectations, and how a tenant should think about the boundary between their
workload and the public internet.

**Deliberately last.** This is the item furthest from our evidence base — we
measure exposure, we have not operated shared GPU infrastructure at scale, and
the people who would read it have. Authoritative-sounding architecture guidance
without operating experience is where credibility gets spent rather than earned.

Worth writing once there is experience behind it.

---

## Deliberately not on this roadmap

- **An operator-requested scan queue.** I-22a specifies it, and building it would
  mean a request intake, an approval path, and a way to deliver results to
  someone who is not a researcher. The web checker already answers a single
  attested host synchronously, and the CLI answers a whole range with no rate
  limit, inside the operator's own boundary. Neither requires us to scan address
  space on request. See `docs/specs/001-reverification-and-disclosure.md`.
- **Anything that proves impact.** I-3 is permanent. We report that an endpoint
  answers an unauthenticated request; we never send the request that would show
  what that access allows.
- **Proxying inference through discovered hosts.** I-20. Not in any phase.
