# ADR 0002: Governed active measurement

- **Status:** accepted and active in production
- **Date:** 2026-08-27
- **Supersedes:** ADR 0001 as the long-term product direction

## Decision

LeakyCompute runs governed third-party re-verification and hosted self-checks.
The control-plane migration, production-owned canary, full invariant suite, and
explicit maintainer activation were completed on 27 August 2026.

The architecture has two deliberately separate boundaries:

1. A single SQLite-backed Cloudflare Durable Object is the strongly consistent
   control plane. At this project's volume, one serialized authority is simpler
   and safer than coordinating D1 rows, KV indexes, and per-host objects. It
   owns probe leases, the authoritative corpus, provenance, exclusions, purge
   jobs, retention scheduling, security counters, and aggregate generations.
2. The API Worker's `cloudflare:sockets` runtime is the only component allowed
   to connect to a target address. It accepts no caller URL or hostname: only a
   consumed permit containing a canonical public IP, reviewed service ID, fixed
   port, operation, and expiry. The sole hostname exception is an isolated,
   disabled-by-default owned-canary profile bound to a configured target and
   marker; third-party traffic never uses DNS.

The API Worker remains the public policy and packet-emission boundary. It calls
the control plane to consume the permit immediately before opening a socket.
Permit consumption is the linearization point for opt-outs: the control plane
re-checks current IP/CIDR/ASN exclusions in the same serialized operation. A
permit denied or already consumed emits no target traffic.

## Control-plane invariants

- A third-party probe lease is persisted before the runner receives permission
  to send a packet. The next eligible time is 14 days later whether the process
  answers, times out, or crashes.
- Public-index provenance is stored with the lease and must be no older than
  seven days. Operator-owned hosted self-checks are a separate purpose and do
  not turn into discovery provenance.
- Active discovery requires a usable ASN bound to the same fresh index record
  as the target address. Missing or conflicting ASN data fails closed, so it
  cannot bypass an ASN-wide exclusion.
- While any ASN-wide exclusion is active, the control plane requires a separate
  BGP mapping before issuing third-party leases. Until that resolver is wired,
  the presence of such an exclusion pauses discovery conservatively.
- Exclusions are authoritative in the control plane. An exclusion becomes
  active before a purge begins and therefore blocks new permits immediately.
- IP, CIDR, and ASN purges are resumable, cover both host and attempt rows, and
  produce a completion receipt only after a verification pass finds no match.
- Retention is driven by indexed due dates and Durable Object alarms, not a
  scan racing a KV TTL.
- Public aggregate generations are built in staging and switched with one
  transactional pointer update only after the complete corpus is counted.
- Authorization, revocation, opt-out, and permit capacity are reserved ahead of
  telemetry. Telemetry failure cannot prevent a security-state write.

## Probe-runtime invariants

- No DNS resolution of target input; the socket destination is the validated IP
  in the consumed permit.
- No environment proxy, redirect following, caller-selected path, arbitrary
  port, request body, or state-changing method.
- Reviewed GET paths only, attributable User-Agent, strict connect/read/total
  deadlines, and a 32 KiB response cap.
- Public-unicast validation is repeated at the service boundary.
- Platform, authorization, timeout, protocol, and target responses are distinct
  result classes. A platform failure can never become a clean target verdict.
- Response data is minimized before it leaves the service and never logged with
  a raw target address.

## Activation record

1. The control plane was implemented and tested locally.
2. KV state was migrated into the authoritative store and reconciled in full.
3. The control plane and socket runtime were deployed with traffic switches off.
4. An isolated operator-owned HTTPS canary verified permit consumption, target
   pinning, response markers, and error taxonomy without touching a third party.
5. The full re-enable suite passed under concurrency, interruption, oversized
   corpus, late-page purge, exclusion races, and runtime failure.
6. The maintainer explicitly activated hosted checks and governed discovery.
7. The first production run exposed runner defects in provenance recovery,
   partial-metric publication, Shodan field compatibility, and overlapping
   hosted/discovery path registries. Each failed closed or was contained; the
   defects were patched, regression-tested, and production re-verified before
   normal scheduling was accepted.

## Why not D1 alone

D1 is queryable and appropriate for many corpus workloads, but the safety path
needs one strongly consistent decision across exclusions, cooldown leases,
rate buckets, and permit consumption. A single low-volume Durable Object already
serializes those decisions and its SQLite backend supplies the required indexes,
transactions, alarms, and point-in-time recovery. This avoids inventing a
distributed transaction between a lease coordinator and the corpus database.

## Consequences

- ADR 0001 remains the historical record of the suspension, but this ADR now
  governs production behavior.
- Workers KV becomes a migration source and optional public cache, not the
  authority for any decision that can permit traffic or deny access.
- Target traffic stays inside the reviewed Worker runtime, avoiding a separate
  probe origin, certificate lifecycle, and bearer-token hop.
- Hosted checks initially cover only the caller's Cloudflare-observed address.
  Arbitrary override checks remain disabled until ownership proof and target ASN
  resolution are independently designed and tested.
