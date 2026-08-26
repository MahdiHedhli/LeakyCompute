# ADR 0001: Passive internet measurement and local-first checks

- **Status:** Accepted
- **Date:** 2026-08-25
- **Decision owner:** Maintainer
- **Supersedes:** active re-verification as an assumed product direction

## Context

LeakyCompute combined three distinct activities: passive measurement from public
indexes, active read-only re-verification of third-party hosts, and defensive
checks initiated inside infrastructure an operator controls. The 2026-08-25
adversarial review found that the active path could emit a request before its
attempt clock was durably persisted, while the current KV corpus, deletion, rate
limit, and reconciliation design could not provide the consistency guarantees
needed at larger scale.

The hosted checker has a separate platform failure: Cloudflare Workers cannot
reliably fetch IP-literal targets. Accepting hostnames would reintroduce DNS
rebinding and opt-out-boundary ambiguity. Presenting either failure as a clean
result would be false assurance.

## Decision

LeakyCompute will use **passive internet measurement plus local operator-owned
checks**.

- Internet-wide research reads supported public-index APIs and publishes
  source-specific counts, overlap, disagreement, freshness, and limitations.
- Live checks run from the local defensive CLI inside infrastructure the
  operator controls.
- Active third-party discovery and hosted checks remain disabled.
- Index records are observations, not permission to contact a host.
- The project will not build an operator-requested remote scan queue as a
  substitute for the local CLI.

Restoring active re-verification would require a new ADR and completion of the
strong-state prerequisites in the security review. It cannot happen through a
flag flip or by reviving the existing runner.

## Code disposition

Keep:

- passive source queries, source-specific plans, and comparison logic;
- the local defensive CLI and reviewed service fingerprints;
- governance tests that document the safety boundary;
- retained historical corpus routes while retention, deletion, opt-out, and the
  gated research purpose still require them;
- the production `/v1/check` kill switch until the disabled endpoint is formally
  removed or replaced.

Retire in bounded follow-up changes:

- live target-request execution and active-ingest modes in the discovery runner;
- configuration and workflow inputs whose only purpose is active probing;
- dormant hosted target-fetch UI/code after compatibility impact is checked;
- documentation that presents historical re-verification as a future default.

Fingerprint logic needed by local checks should be extracted before deleting a
dormant remote path. Historical records remain subject to I-25 deletion and
I-26 retention; choosing passive mode is not permission to abandon those duties.

## Consequences

Benefits:

- no project-originated traffic to third-party targets;
- substantially smaller abuse, consistency, retention, and opt-out risk;
- product work aligns with the operator's authority boundary;
- published measurements can expose source bias instead of disguising it.

Costs and limitations:

- passive counts do not prove that an endpoint is currently reachable or
  unauthenticated;
- historical re-verification counts become increasingly stale and must stay
  labeled historical;
- source licenses constrain storage, publication, and redistribution;
- tunnelled and poorly indexed services remain structurally undercounted.

## Verification

- Production `/v1/check` returns `503 hosted_checks_temporarily_disabled` before
  parsing a target.
- The scheduled discovery workflow sends no traffic to target hosts and uploads
  no address-level artifact.
- Active runner entry points remain fail-closed until removed.
- Public and repository documentation describe passive counts, historical
  re-verification, and local checks as separate measurements.
