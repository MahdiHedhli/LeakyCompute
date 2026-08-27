# Adversarial security review — 2026-08-25

## Activation addendum — 2026-08-27

This document preserves the suspension decision and evidence as of 25 August.
The architectural blockers below were subsequently implemented as a single
SQLite-backed Durable Object control plane plus an address-pinned Worker socket
runtime. The production migration, authoritative pagination, resumable purge,
indexed retention, generation-switched reconciliation, owned canary, and full
re-enable suite completed before the maintainer explicitly activated hosted
self-checks and governed discovery on 27 August. ADR 0002 is the current
production authority.

The first governed production run exposed four additional defects:

- a public Actions log briefly received raw Shodan/API response material before
  the run was deleted; responses are now minimized and all error logging reports
  shape/status only;
- a historical source label without an observation timestamp was incorrectly
  converted into fresh provenance, producing one target attempt; missing or
  malformed timestamps now fail closed and historical membership alone cannot
  authorize traffic;
- a failed or subset passive lane could overwrite the complete public index
  measurement; only a successful all-lane run may publish that metric, and the
  last complete value was restored;
- overlapping hosted and discovery service profiles rejected the reviewed
  discovery path at the socket boundary; the registries now union their reviewed
  paths and an end-to-end regression covers the overlap.

Passive lane failures now abort before corpus reads or target work, workflow
logs contain no raw target addresses, and the corrected path was re-tested in a
capped production run. These incidents remain part of the audit trail rather
than being rewritten out of the original review.

## Status

Daybreak Blue and the primary agent reviewed the Worker, static clients,
research lab, Pages bridge, discovery runners, storage model, GitHub Actions,
Cloudflare configuration, local CLI, and test suite. No third-party target was
probed during the review.

The review found defects that made the deployed safety claims stronger than the
implementation. Immediate containment is now fail-closed:

- hosted `/v1/check` is disabled in production;
- public overrides are disabled;
- scheduled and local active discovery are disabled;
- discovery workflow artifacts are no longer uploaded;
- the researcher identity bypass is closed.

The hardened Worker was deployed through the documented local Wrangler OAuth
path on 2026-08-25 as version
`ead92748-81ef-4035-b838-f1bcc3189c13`. A packet-free live discriminator
confirmed that `/v1/check` returns `503 hosted_checks_temporarily_disabled`
before parsing the request body.

Dry-run discovery, the local operator-owned CLI, aggregate statistics, and the
Access-gated lab remain available.

## Confirmed findings addressed or contained

| Severity | Finding | Resolution |
|---|---|---|
| Critical | Any valid Access user could add `X-GitHub-Login` naming an allowlisted researcher and read the raw corpus. Email local-parts and mutable display claims created equivalent identity collisions. | Production identity now comes only from the exact email in a cryptographically verified Access app JWT. JWT issuer, audience, type, lifetime, algorithm, signature and exact key ID are checked. Behavioral token tests cover spoofing and tampering. |
| Critical | Scheduled workflow artifacts and console output exposed raw candidate/target addresses in a public repository, bypassing I-14/I-27. | Artifact upload removed; all per-address console paths redacted; the root output filename is ignored. Historical artifacts and logs were removed and verified as described below. |
| High | The hosted checker targets IP literals, but Cloudflare Workers global `fetch` does not support direct IP-literal destinations. A platform refusal could appear as a clean result. | `HOSTED_CHECKS_ENABLED=false` in production; `/v1/check` returns an honest 503 before parsing or writing KV. See Cloudflare's [known issue](https://developers.cloudflare.com/workers/platform/known-issues/#fetch-to-ip-addresses). |
| High | Target validation missed documentation, benchmarking, multicast and reserved ranges; accepted ambiguous numeric encodings; and hostname resolution enabled DNS rebinding and CIDR opt-out bypass. | Canonical IPv4/IPv6 parser, public-unicast classification, hostname rejection, and exhaustive boundary tests added. Overrides remain suspended because target-ASN opt-outs cannot yet be proven. |
| High | Active discovery writes the I-24 attempt clock only after a completed run. A crash after sending packets could leave targets eligible on the next run. The ledger capacity could also evict entries before 14 days. | Scheduled and local active modes now refuse to run. Ledger bound increased as defense in depth, but live operation stays blocked until a durable pre-probe lease exists. |
| High | `scripts/discovery/discover.py` could probe arbitrary seeds/neighborhoods without current provenance, exclusion, interval, port and bucket gates. | Legacy active mode disabled; passive reports and packet-free plans remain. |
| High | Duplicate `services` values amplified one request into many target GETs and OSV calls; inherited object keys such as `constructor` passed loose registry checks; non-boolean authorization values were truthy. | Service IDs are exact, deduplicated and bounded; registry access uses own keys; attestation requires boolean `true`; regression tests count emitted target requests. |
| High | Research aliases survived some re-approval/revocation sequences and aliases could overwrite another researcher's identity. | Alias ownership conflicts fail before writes; removed aliases are deactivated; alias matches re-check the active primary; revoke-through-alias and rotation sequences are tested. |
| High | The Pages bridge's fixed-looking prefix could normalize `../` into an admin path and it forwarded an obsolete client identity header. | Exact route inventory, encoded traversal refusal, narrow header forwarding, manual redirects, no-store response, and a behavioral bridge suite added. `functions/**` now triggers deployment verification. |
| High | A trusted/stale index record could launder a private/reserved target or act as standing probe permission long after the listing. | Public-unicast check precedes provenance; index observations expire after seven days; stale/non-public cases are tested. Active mode remains off. |
| High | LiteLLM `/health` can issue paid model completions. A stale profile still named it even though the runner used static `/health/liveliness`. | Profile corrected and cross-file regression added. |
| Medium | Off-Worker HTTP reads were unbounded. | Success and error bodies are capped at 32 KiB. |
| Medium | Partial reconciliation scanned the newest 2,000 records and overwrote complete aggregates as if the partial result were complete. | Reconciliation now checkpoints a fixed index snapshot and its staging counters across bounded calls, restarts if the authoritative index changes, and publishes only after the full snapshot is processed. Regression verifies partial calls cannot overwrite live aggregates. |
| Medium | An approved broad exclusion label could be reused after the issue author edited the requested scope. The workflow also claimed deletion even when the bounded purge was incomplete. | Broad permission is valid only on the approval-label event for the current body. Comments distinguish active suppression from pending deletion. |
| Medium | Research approval parsed the wrong issue-form label and constructed JSON with shell string interpolation. | Correct field is parsed and validated; `jq` constructs approval/revocation payloads. |
| Medium | Denied lab requests stored a raw signed email inside abuse-log metadata; lab scans could exceed practical KV read budgets. | Identity is hashed through the target field, not stored in metadata. Scan cap reduced to 400 with short-window and daily per-user limits. |
| Medium | Abuse-log IP pseudonyms used a public fallback salt, making IPv4 values cheaply enumerable if the production secret was absent. | Pseudonyms now use HMAC-SHA-256. Production skips the log entry if `ABUSE_LOG_SALT` is absent; only test/development has an explicit local fallback. |
| Medium | Admin ingest treated an unreadable authoritative exclusion list as empty and allowed a caller snapshot to replace it. | Ingest now fails closed on an exclusion-store error and unions any caller snapshot with the authoritative list. Regression tests cover outage and stale-snapshot cases. |
| Medium | Local HTTP helpers followed redirects; the Ollama CLI had unbounded reads and non-loopback single-host checks required no attestation; favicon HTML could point at another origin. | Redirects are disabled, response bodies are capped, URL schemes/credentials are validated, cross-origin favicon fetches are refused, and non-loopback checks require an ownership attestation. |
| Low | Production pages accepted arbitrary `?api=` endpoints, disclosure-window misconfiguration could make rows immediately publishable, browser policy was weak, and generic error responses exposed exception strings. | Query overrides are local-development only; disclosure is clamped to 1–90 days; CSP/referrer/security headers were added where the hosting platform supports them; public exception responses now contain only request IDs. |

## Open architectural blockers

These are not resolved by a local patch. They remain security work, and active
probing must stay disabled until the first three are complete.

1. **Durable pre-probe attempt ledger.** Acquire a strongly consistent per-host
   lease before the packet; make the lease cover 14 days whether the target
   answers or the process crashes. KV read/modify/write is not sufficient.

2. **Authoritative pageable corpus storage.** `discovery:hits_index` is a bounded
   array. Once it trims an address, the record can become invisible to listing,
   retention, reconciliation and opt-out deletion until TTL. Move host records,
   attempt clocks and purge state to D1/Durable Objects or another queryable,
   transactional store.

3. **Resumable, verifiable opt-out deletion.** ASN purge currently scans a
   bounded slice and attempt rows do not carry an ASN. Removal must persist a
   cursor, finish every matching host/attempt row, and report completion only
   after verification. Suppression remains immediate, but deletion is not yet
   provably complete for a large ASN request.

4. **Retention scheduling versus corpus size.** A daily bounded sweep can take
   longer than the seven-day TTL grace as the corpus grows. A TTL-expired record
   loses the metadata needed to decrement aggregates. Expiry needs queryable
   due dates/jobs and deletion metadata, not a scan of a bounded array.

5. **Separate security state and budgets.** Rate counters, telemetry, corpus,
   exclusions and researcher authorization share eventually consistent Workers
   KV and its account-wide write budget. Put authorization/exclusions in strong
   storage, use Cloudflare Rate Limiting or Durable Objects for counters, and
   reserve capacity for revocation/removal ahead of telemetry.

6. **Corpus query economics.** The lab cap/rates are now conservative, but a
   queryable store is still needed to avoid one KV read per host and isolate-
   local cache behavior.

7. **Public statistics read isolation — remediated 2026-08-25.** Workers Caching
   now serves the canonical `/v1/stats` representation before Worker execution.
   A native edge limiter rejects cold-miss/cache-bypass floods before any KV
   read, alternate cache-key forms are refused, and the route fails closed in
   production when the limiter is unavailable. The response has a 30-second
   browser TTL and 60-second Cloudflare edge TTL; at most two cold-miss origin
   builds are admitted per minute in each Cloudflare location. The limiter is
   local and eventually consistent, so the controlled-hostname/WAF item remains
   the next perimeter layer rather than being implied complete here.

8. **CI and dependency supply-chain pinning.** GitHub Actions use mutable
   major-version tags; Wrangler has a range without a lockfile; local-lab
   containers use mutable tags/runtime installation; and no required workflow
   runs the test suite. Pin reviewed action SHAs, exact package versions and
   image digests, commit a lockfile, scope credentials to the one step needing
   them, and make the full suite a required check.

9. **Resumable aggregate reconciliation.** Refusing a partial 2,000-row recount
   prevents further corruption but cannot heal a larger corpus. Recount into
   versioned staging state with a persisted cursor, then switch generations
   only after the complete index has been processed.

## Additional hardening before re-enabling traffic

- Treat candidates with unknown ASN as a conservative shared rate bucket; do
  not skip the per-ASN gate.
- Put the Worker behind a controlled custom hostname/WAF before turning off the
  direct `workers.dev` exposure.
- Enforce clickjacking headers for the GitHub Pages site at a proxy/CDN that can
  set response headers; its in-document CSP cannot enforce `frame-ancestors`.

## Incident response completed

The review found public Actions artifacts and historical log lines containing
raw address-level discovery data. The response was completed on 2026-08-25:

1. Captured an ignored, local incident inventory containing only run/artifact
   IDs, timestamps and commit SHAs. Artifact contents were not downloaded.
2. Deleted all 13 `discovery-run` artifacts from the affected August 19–25
   window. A paginated repository query then returned zero matching artifacts.
3. Deleted the log sets for all 13 corresponding workflow runs. HEAD checks on
   every log endpoint returned HTTP 404 after deletion.
4. Removed the scheduled active workflow and artifact-upload path; future
   operation is packet-free dry-run only.
5. Reviewed source and workflow output paths for credential disclosure. No
   Shodan, admin or Cloudflare credential leak was confirmed, so credential
   rotation was not indicated by the available evidence.

Deletion cannot revoke copies downloaded or cached before containment. That
residual exposure remains part of the incident record and must inform any future
host-identifying publication or operator notification under I-27.

## Re-enable criteria

Hosted checks may be re-enabled only behind a trusted probe service that can pin
validated addresses, enforce public-unicast and ASN/CIDR exclusions, use strong
rate limits, and return a distinguishable platform error rather than a clean
verdict.

Active discovery may be re-enabled only after durable pre-probe leases,
resumable opt-out deletion, authoritative pageable storage, and a security-state
write budget are implemented and adversarially tested.

## Verification

- `npm test` passes, including target-boundary, signed Access JWT, Pages bridge,
  route-gating, no-proxy, retention, exclusion, reconciliation and discovery
  governance suites.
- Python and JavaScript syntax checks pass.
- `.secrets.local.json`, address-level local outputs, and `discovery-run.json`
  are ignored; the local secrets file remains mode `0600`.
- Live `/v1/check` returned `503 hosted_checks_temporarily_disabled` for a body
  that the prior deployment handled as `400 authorization_required`; the
  discriminator cannot emit a target request in either version.
- The public pause notice, Access redirect, zero remaining discovery artifacts,
  and 13 deleted log endpoints were verified remotely.

## 2026-08-27 Daybreak Blue follow-up

A second adversarial pass after re-enablement found three high-severity edge
cases. They were treated as new blockers: the scheduled workflow was paused
again before remediation.

- Active discovery now fails closed when ASN data is missing, and the Worker
  verifies that the fresh provenance record is bound to the same IP and ASN.
  Because the nominating index cannot independently validate its own ASN data,
  any ASN-wide opt-out pauses discovery until a separate BGP mapping is present.
- ASN-facet candidates preserve Shodan's own observation timestamp; missing or
  malformed timestamps are never replaced with the current time.
- Opt-outs activate in the Durable Object before the KV mirror or workflow
  confirmation. A failed activation returns 503 and cannot add the
  `exclusion-active` label.

The same pass also tightened hosted-check concurrency and plan validation,
added service-specific response validation, capped public request bodies,
moved researcher authorization/revocation into transactional strong storage,
fixed composite purge pagination, preserved authoritative geography, enforced
the 128-candidate run ceiling, and made runner/control failures visible. No
approval or revocation workflow runs existed in the repository history, so no
email-bearing Action logs required deletion.
