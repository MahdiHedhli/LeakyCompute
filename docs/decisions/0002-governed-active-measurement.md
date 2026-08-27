# ADR 0002: Governed active measurement

- **Status:** accepted for implementation; traffic remains disabled
- **Date:** 2026-08-27
- **Supersedes:** ADR 0001 as the long-term product direction

## Decision

LeakyCompute will build the controls required for governed third-party
re-verification and hosted self-checks. This decision authorizes architecture,
migration, dark deployment, and packet-free verification. It does not authorize
target traffic before the re-enable suite passes and the maintainer makes a
separate activation decision.

The architecture has two deliberately separate boundaries:

1. A single SQLite-backed Cloudflare Durable Object is the strongly consistent
   control plane. At this project's volume, one serialized authority is simpler
   and safer than coordinating D1 rows, KV indexes, and per-host objects. It
   owns probe leases, the authoritative corpus, provenance, exclusions, purge
   jobs, retention scheduling, security counters, and aggregate generations.
2. A small external probe service is the only component allowed to connect to a
   target address. The API Worker reaches it over mTLS at a dedicated unproxied
   service hostname. It accepts no caller URL or hostname: only a canonical
   public IP, reviewed service ID, and one-time permit bound to that address,
   port, operation, and expiry.

The API Worker remains the public policy boundary. The probe service calls back
to consume the permit immediately before opening a socket. Permit consumption
is the linearization point for opt-outs: the control plane re-checks the current
IP/CIDR/ASN exclusions and rate limits in the same serialized operation. A
permit denied or already consumed emits no target traffic.

## Control-plane invariants

- A third-party probe lease is persisted before the runner receives permission
  to send a packet. The next eligible time is 14 days later whether the process
  answers, times out, or crashes.
- Public-index provenance is stored with the lease and must be no older than
  seven days. Operator-owned hosted self-checks are a separate purpose and do
  not turn into discovery provenance.
- Unknown ASN is the shared `AS-UNKNOWN` bucket and receives the most
  conservative rate limits. It never bypasses an ASN gate.
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

## Probe-service invariants

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

## Staged activation

1. Implement and test the control plane locally.
2. Migrate KV state and compare it read-only against current production.
3. Deploy the control plane dark; keep both traffic kill switches off.
4. Deploy the probe service with test-only/documentation-range fixtures and
   verify mTLS, permit replay refusal, target pinning, and error taxonomy.
5. Run the full re-enable suite under concurrency, interruption, oversized
   corpus, late-page purge, exclusion races, and service failure.
6. Present the evidence and exact first-run bounds to the maintainer. Activation
   is a separate, explicit decision.

## Why not D1 alone

D1 is queryable and appropriate for many corpus workloads, but the safety path
needs one strongly consistent decision across exclusions, cooldown leases,
rate buckets, and permit consumption. A single low-volume Durable Object already
serializes those decisions and its SQLite backend supplies the required indexes,
transactions, alarms, and point-in-time recovery. This avoids inventing a
distributed transaction between a lease coordinator and the corpus database.

## Consequences

- ADR 0001 remains the authority for current production behavior until the
  activation decision. Passive/local-first mode is still live today.
- Workers KV becomes a migration source and optional public cache, not the
  authority for any decision that can permit traffic or deny access.
- The external probe origin is new infrastructure with its own patching,
  certificate rotation, egress policy, monitoring, and incident-response burden.
- Hosted checks initially cover only the caller's Cloudflare-observed address.
  Arbitrary override checks remain disabled until ownership proof and target ASN
  resolution are independently designed and tested.
