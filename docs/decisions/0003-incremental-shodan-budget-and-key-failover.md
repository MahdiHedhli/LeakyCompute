# ADR 0003: Incremental Shodan budget and governed credential failover

- **Status:** proposed for the next sprint
- **Date:** 2026-09-02
- **Blocks:** switching the production discovery account to a lower Shodan tier

## Context

The current paid-plan setting permits up to 10 result pages per lane. With every
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

Implement an incremental Shodan scheduler backed by a strongly consistent,
month-scoped source-credit ledger:

1. Reserve a query unit before every Shodan request, including retries. If the
   ledger cannot be read or the reservation cannot be committed, make no
   provider request.
2. Configure a conservative monthly ceiling and a separate reserve without
   committing either API key. The late daily run is bounded by both remaining
   Shodan credits and remaining Workers KV capacity.
3. Replace the fixed 10-page production behavior with small cursor-based page
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

## Sprint implementation order

1. Confirm the target Shodan plan's current monthly allowance, request charging
   rules, retry behavior, and multi-credential terms from primary documentation.
2. Add a source-budget table and authenticated aggregate health endpoint to the
   existing Durable Object. Budget state must include month, reserved, consumed,
   remaining, reserve, and reset time—never keys or raw target data.
3. Add reserve/commit/release operations with concurrency and crash tests.
   Ambiguous requests remain consumed rather than being optimistically refunded.
4. Teach the nominator to request one bounded page slice at a time and to stop
   before the next provider call when the reservation is unavailable.
5. Add the optional secondary secret and disabled-by-default promotion flag.
6. Update scheduled preflight to calculate the run envelope from the minimum of
   source-credit capacity, KV capacity, and the reviewed candidate ceiling.
7. Canary with the secondary unset, then with a deliberately invalid primary
   and an operator-enabled test secondary. Verify that quota/rate responses do
   not fail over and that logs remain public-safe.
8. Run the full invariant suite and a fresh adversarial review before enabling
   automatic promotion or switching away from the paid plan.

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
