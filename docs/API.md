# LeakyCompute Worker API

Base URL: `https://leakycompute-api.mhedhli.workers.dev` (see `public/js/config.js`)

Source of truth is [`worker/src/index.js`](../worker/src/index.js). This document
describes the contract; when they disagree, the code wins and this file is a bug.

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/` , `/v1/health` | GET | none | liveness |
| `/v1/stats` | GET | none | public aggregate counters |
| `/v1/check` | POST | Turnstile (if configured) | the self-check |
| `/v1/research/me` | GET | Cloudflare Access | researcher identity + allowlist state |
| `/v1/research/catalog` | GET | Access + allowlist | gated catalog |
| `/v1/admin/allowlist` | POST | `X-Admin-Token` | approve / revoke researchers |
| `/v1/admin/discovery/hits` | GET | `X-Admin-Token` | private hit list (raw IPs) |
| `/v1/admin/discovery/ingest` | POST | `X-Admin-Token` | ingest off-Worker discovery runs |

CORS is allowlisted via the `ALLOWED_ORIGINS` var. All responses are
`Cache-Control: no-store` except `/v1/stats` (`max-age=30`).

---

## POST /v1/check

The public self-check. Probes Ollama, Ray and Jupyter **in parallel** and returns
a structured report.

Every request this endpoint makes to a target is a read-only `GET`. See
[SECURITY.md](SECURITY.md) for the invariants that constrain it.

### Request

All fields optional. **An empty body is the common path** — the target defaults
to the caller's `CF-Connecting-IP`.

```json
{
  "target": "host.example.com",
  "authorized": true,
  "services": ["ollama", "ray", "jupyter"],
  "ports": { "ollama": 11435 },
  "turnstile_token": "..."
}
```

| Field | Type | Notes |
|---|---|---|
| `target` | string | Hostname or public IP. Presence switches to override mode. |
| `authorized` | bool | **Required when `target` is set.** Attests ownership/authorization. |
| `services` | string[] | Subset of `["ollama","ray","jupyter"]`. Defaults to all. Unknown names are dropped; an all-unknown list is a 400. |
| `ports` | object | Per-service port override, validated against that service's allowlist. |
| `port` | number | **Legacy.** Mapped to `ports.ollama`. Still allowlist-checked. |
| `turnstile_token` | string | Required only when `TURNSTILE_SECRET_KEY` is set. |

**Port allowlist** — this endpoint is not a general-purpose port prober:

| Service | Default | Accepted |
|---|---|---|
| ollama | 11434 | 11434, 11435 |
| ray | 8265 | 8265, 8266 |
| jupyter | 8888 | 8888, 8889, 8890 |

### Response `200`

```json
{
  "ok": true,
  "mode": "own_ip",
  "target": "your_egress_ip",
  "checked_at": "2026-08-10T12:00:00.000Z",
  "overall_severity": "critical",
  "any_exposed": true,
  "services": [ /* see below */ ],
  "guidance": "...",
  "limitations": "A clean result is not proof of safety. ...",

  "port": 11434,
  "exposed": true,
  "auth_required": false,
  "latency_ms": 41,
  "models": [{ "name": "llama3.2:3b", "size": 2019393189 }],
  "error": null
}
```

`mode` is `own_ip` or `override`. In `own_ip` mode `target` is the literal string
`"your_egress_ip"` — **the caller's IP is never echoed back**.

`overall_severity` is the worst severity across all findings on detected
services, ordered `none < info < low < medium < high < critical`.

The last six fields are **legacy compatibility**, mirroring the Ollama result for
pre-tier-1 clients. Nothing in this repo reads them. Safe to remove once no
deployed client depends on them.

### Service result object

```json
{
  "service": "ollama",
  "label": "Ollama",
  "port": 11434,
  "detected": true,
  "version": "0.32.6",
  "exposed": true,
  "authenticated": false,
  "latency_ms": 41,
  "status": 200,
  "error": null,
  "models": [{ "name": "llama3.2:3b", "size": 2019393189 }],
  "jobs_visible": 0,
  "osv": [ /* tier-2, see below */ ],
  "findings": [
    {
      "id": "ollama-unauth-api",
      "title": "Unauthenticated Ollama API exposed",
      "severity": "high",
      "detail": "...",
      "endpoint": "/api/tags"
    }
  ],
  "remediation": ["Bind Ollama to 127.0.0.1 ...", "..."]
}
```

| Field | Notes |
|---|---|
| `detected` | Service confirmed. Timeout / refused / filtered ⇒ `false`, **never an error**. |
| `version` | `null` when the service exposes none. **Jupyter always returns `null`** — `jupyter_server`'s `/api/status` carries no version field. |
| `exposed` | The read-only exposure endpoint answered without auth. |
| `authenticated` | The service rejected the unauthenticated read (401/403, or a redirect to a login page). |
| `models` | Ollama only. Capped at 25. |
| `jobs_visible` | Ray only. Count, not contents. |
| `findings` | Empty when `detected` is false. |

**States that matter:**

| `detected` | `exposed` | `authenticated` | Meaning |
|---|---|---|---|
| false | false | false | Nothing observed on that port |
| true | false | true | Reachable, auth enforced → `*-reachable` finding (low/medium) |
| true | true | false | **Open** → the service's exposure finding (high/critical) |

### Findings

Static findings emitted by [`services.js`](../worker/src/lib/services.js):

| id | Severity | Condition |
|---|---|---|
| `ollama-unauth-api` | high | `GET /api/tags` returned a model list |
| `ollama-reachable` | low | detected, not exposed |
| `ray-unauth-jobs-api` | critical | `GET /api/jobs/` returned an array |
| `ray-reachable` | medium | detected, not exposed |
| `jupyter-no-token-auth` | critical | `GET /tree` rendered without a login redirect |
| `jupyter-reachable` | low | detected, not exposed |

Ray is flagged on **configuration, not version**: CVE-2023-48022 is disputed
because the vendor considers the missing auth intentional, so version matching
would never fire. Upgrading does not clear it.

### Tier-2: OSV enrichment

When a service is `detected` **and** carries a `version`,
[`osv.js`](../worker/src/lib/osv.js) queries OSV.dev and populates `osv[]`:

```json
{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "cve": "CVE-2024-37032",
  "aliases": ["CVE-2024-37032"],
  "title": "...",
  "severity": "high",
  "source": "osv.dev",
  "published": "...", "modified": "...",
  "references": ["https://..."]
}
```

Package mapping: ollama → `Go:github.com/ollama/ollama`, ray → `PyPI:ray`,
jupyter → `PyPI:jupyter_server`. Results cached in KV for 24h, capped at 12 per
service.

Two behaviours worth knowing:

- **Only the top 5 OSV hits are merged into `findings`, and only when the service
  is `exposed`.** A detected-but-authenticated service still populates `osv[]` but
  does not inflate `overall_severity`.
- Because merged OSV findings carry their own severity, `overall_severity` is
  version-aware, not just exposure-aware.

Jupyter never gets OSV results in practice — it reports no version.

### Errors

| Status | `error` | Cause |
|---|---|---|
| 400 | `authorization_required` | `target` set without `authorized: true` |
| 400 | `missing_target` / `invalid_target` / `invalid_hostname` / `target_too_long` | target validation |
| 400 | `private_target_not_allowed` | RFC1918/loopback/link-local/CGNAT target |
| 400 | `port_not_allowed` | port outside that service's allowlist; response includes `allowed_ports` |
| 400 | `unknown_service` | every name in `services` unrecognized; response includes `supported` |
| 403 | `turnstile_failed` | Turnstile verification failed |
| 429 | `rate_limited` | includes `scope` (`global` \| `own_ip` \| `override`) and `reset` (epoch seconds) |

### Rate limits

Deployed values from `wrangler.toml` (code fallbacks in parentheses, used only if
the var is unset):

| Scope | Window | Max |
|---|---|---|
| own IP | 900s | 3 (5) |
| own IP | 24h | 12 (20) |
| override | 900s | 1 (2) |
| override | 24h | 3 (5) |
| global | 24h | 800 (2000) |

Limits are counted **per check request**, not per outbound probe. One check
issues at most 9 GETs — per service, up to 2 confirm attempts plus 1 exposure
probe. Fewer in practice: the confirm loop stops at the first match, the exposure
probe is skipped entirely when the service isn't confirmed, and a transport
failure on the first confirm skips the fallback rather than burning a timeout.

---

## GET /v1/stats

Public aggregates. Never contains raw IPs.

```json
{
  "research_snapshot": { "label": "...", "models": 1864, "hosts": 19348, "note": "..." },
  "live_instrumented": {
    "checks_total": 0, "exposed_total": 0, "last_check_at": null,
    "models_top": [{ "model": "llama3.2:3b", "count": 12 }],
    "by_service": { "ollama": { "checks": 0, "detected": 0, "exposed": 0 } },
    "discovery_runs": 0, "last_discovery_at": null, "note": "..."
  },
  "geography": {
    "by_country": [{ "country": "US", "count": 64 }],
    "by_asn": [...], "by_stack": [{ "stack": "ollama", "count": 12 }]
  },
  "updated_at": "...",
  "methodology": "..."
}
```

`by_stack` counts host+stack pairs, so a host first seen as Ollama that later
exposes Jupyter increments both.

---

## Gated endpoints

**`GET /v1/research/me`** — resolves Cloudflare Access identity.
`401` unauthenticated, `403` recognized but not allowlisted, `200` allowed.
Returns `{ authenticated, allowed, login, email, dev, entry, message }`.

**`GET /v1/research/catalog`** — Access + allowlist required. Returns the
validated catalog, snapshot counts, and live aggregates. `chat_enabled` is
`false` at launch.

---

## Admin endpoints

All require `X-Admin-Token` matching `ADMIN_SYNC_TOKEN`. `401` otherwise, and
failures are written to the private abuse log.

**`POST /v1/admin/allowlist`** — `{ op: "approve" | "revoke", login, issue_number?, approved_by?, meta? }`

**`GET /v1/admin/discovery/hits`** — `?limit` (≤2000, default 500), `?sort=last_seen|country|asn`.
**Returns raw IPs.** Admin-only, never proxied to a public surface.

**`POST /v1/admin/discovery/ingest`** — `{ results: [...], run_meta? }`.
Batches capped at 150; rate-limited to 10/hour.

---

## Notes for clients

- **Never render `services[].version`, `models[].name`, or finding text as HTML
  without escaping.** In override mode these are attacker-controlled strings from
  the probed host. `public/js/app.js` escapes everything it interpolates.
- Treat `detected: false` as "not observed", not "safe" — surface `limitations`
  alongside any clean result.
