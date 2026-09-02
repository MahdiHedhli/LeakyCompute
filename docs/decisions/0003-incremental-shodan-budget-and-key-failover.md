# ADR 0003: Incremental Shodan budget and governed credential failover

- **Status:** accepted and implemented; secondary credential not provisioned
- **Date:** 2026-09-02
- **Blocks:** switching the production discovery account to a lower Shodan tier

## Context

The former paid-plan setting permitted up to 10 result pages per lane. With every
reviewed lane covered once by the daily shards and again by the pre-reset
catch-up, that is intentionally a transitional burn-down configuration. It is
not an acceptable steady state for a monthly-limited account.

Per-lane cursors already prevent ordinary runs from buying the same first page
repeatedly, but they do not impose a shared monthly source budget. Retries also
consume provider requests. Workers KV headroom and Shodan search allowance are
different resources and must be governed separately.

A secondary Shodan credential is available for future continuity. Its existence
does not authorize doubling the project's quota or bypassing a provider limit.
Current plan limits and API terms must be rechecked at sprint kickoff; no exact
free-tier allowance is encoded in this decision.

## Decision

LeakyCompute uses an incremental Shodan scheduler backed by a strongly consistent,
month-scoped source-credit ledger:

1. Atomically consume a query unit before every Shodan request, including retries. If the
   ledger cannot be read or the reservation cannot be committed, make no
   provider request.
2. Configure a conservative monthly ceiling and a separate reserve without
   committing either API key. The late daily run is bounded by both remaining
   Shodan credits and remaining Workers KV capacity.
3. Replace the fixed 10-page production behavior with one-page cursor-based
   slices. Each regular shard buys only its assigned incremental slice. The
   pre-reset run may use unused daily capacity but cannot exceed the remaining
   monthly source budget.
4. Persist one cursor per lane and advance it only after that lane's accepted
   response and cursor update commit. A failed passive lane retains its page.
5. Keep one shared credit ledger across the primary and secondary credentials.
   Changing credentials never creates a second budget.

## Credential failover policy

- Store credentials only as GitHub Actions secrets, provisionally named
  `SHODAN_API_KEY_PRIMARY` and `SHODAN_API_KEY_SECONDARY`. Never accept them as
  workflow inputs, write them to artifacts, or emit derived key identifiers.
- The primary remains the only active credential by default. The secondary is a
  disabled break-glass path until current Shodan terms and account ownership
  permit its use and the maintainer explicitly enables failover.
- Rate limits, exhausted credits, plan restrictions, and other provider denials
  do **not** trigger key failover. The lane stops and retains its cursor.
- Transient transport and provider failures use the existing bounded retries on
  the same credential. A provider-wide outage does not justify switching keys.
- A revoked or invalid primary may fail over only when the feature flag is
  enabled, the secondary passes a minimal account-health check, and the shared
  ledger has budget. Record only aggregate slot/status telemetry such as
  `primary_unavailable` and `secondary_promoted`; never log provider response
  bodies or credential material.
- Promotion uses a circuit breaker for the rest of the run. Do not alternate
  credentials per request or race them concurrently.

## Implementation record

1. The existing Durable Object now holds a month-scoped consumed-unit value in
   its SQLite metadata and updates it transactionally.
2. The paced ceiling grows continuously through the month. Unused allowance
   carries forward, while early runs cannot front-load the whole month.
3. Admin and nominator health routes return aggregate budget state only. The
   nominator consumes one unit immediately before each provider call.
4. Search lanes read one page per invocation. ASN lanes rotate through two
   provider groups at a time instead of rereading every top ASN.
5. Scheduled preflight stops before index access when either source pacing or
   Workers KV headroom is unavailable.
6. The optional secondary secret and promotion path exist but remain inert while
   `SHODAN_SECONDARY_FAILOVER_ENABLED=false` and the secret is unset.
7. Tests verify pre-request accounting, retry charging, monthly pacing, route
   isolation, and refusal to fail over for rate limits.

Before changing the production Shodan tier or enabling the secondary, confirm
the current allowance, charging rules, and multi-credential terms from Shodan's
primary documentation. Then run an operator-approved failover canary and fresh
adversarial review.

## Acceptance criteria

- A month cannot spend more provider requests than the configured shared cap,
  even with overlapping jobs, retries, crashes, or both credentials configured.
- A failed lane neither advances its cursor nor consumes additional unreserved
  provider calls.
- Scheduled runs are incremental and distribute the monthly allowance instead
  of front-loading it.
- Provider quota exhaustion stops index access without changing credentials.
- Missing or degraded budget state fails before Shodan access and target traffic.
- No key, key fingerprint, provider response body, raw address, or private
  account identifier appears in logs, artifacts, public metrics, or commits.

## Non-goals

This change does not combine Shodan accounts to manufacture a larger quota, make
Shodan a permanent single source, or change the active-probe safety envelope.
Censys remains the planned independent census source.
