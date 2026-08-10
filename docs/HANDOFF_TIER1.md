# Handoff — Tier-1 multi-service checker (v1)

**Context for the next model:** Grok built LeakyCompute. Claude (Opus) implemented the
tier-1 checker described in the "LeakyCompute Checker — Build Brief" on top of it.
This document is the merge brief: what changed, why, what's verified, and what's left.

Working tree: `<REDACTED_LOCAL_PATH>s/Coding/ThreatResearch/<redacted-project>/LeakyCompute`
Nothing is committed. No commits were made and Claude was not added as a co-author.

---

## What shipped

`POST /v1/check` went from a single Ollama `GET /api/ps` probe to a structured
three-service report (**Ollama 11434, Ray 8265, Jupyter 8888**), probed in parallel.

### New file: `worker/src/lib/services.js`

The whole tier-1 engine. A declarative registry plus a probe runner.

Each service declares `confirm` steps (first match wins, yields version), one
`exposure` step, a `finding` for when exposure is confirmed, a `reachableFinding`
for detected-but-not-exposed, and a `remediation` list.

| Service | Confirm | Exposure check | Finding when true | Severity |
|---|---|---|---|---|
| Ollama | `GET /api/version` → `{version}`; fallback `GET /` → "Ollama is running" | `GET /api/tags` returns model list | `ollama-unauth-api` | high |
| Ray | `GET /api/version` → `{ray_version}`; fallback `GET /` title | `GET /api/jobs/` returns array | `ray-unauth-jobs-api` | critical |
| Jupyter | `GET /api/status` → `{started,version}`; fallback `GET /` (302→`/login` counts) | `GET /tree` renders without login redirect | `jupyter-no-token-auth` | critical |

Design points worth keeping:

- **Exposure probes only run after confirm succeeds.** Non-services never get a
  second request.
- **Ollama vs Ray both serve `/api/version`.** Ollama's matcher explicitly requires
  `ray_version === undefined`; Ray's requires `ray_version` present. There's a
  regression test for this.
- **Ray is flagged on configuration, not version** — per the brief. CVE-2023-48022
  is disputed because the vendor considers missing auth intentional, so version
  matching would never fire. The finding text says so explicitly.
- **Bodies are read through `readCapped()` (32 KB).** In override mode the target is
  attacker-controlled and could otherwise stream unbounded data at the Worker.
- **`redirect: "manual"` everywhere.** A redirect must never carry us to another host.
- **Timeout/connection failure ⇒ `detected: false`**, never a surfaced error — as specified.

### Modified

- **`worker/src/index.js`** — `handleCheck` now runs `runChecks()` and returns the
  structured report. Turnstile, rate limits, attestation gate, and private-target
  rejection are untouched and still run *before* any probe.
- **`worker/src/lib/check.js`** — reduced to target validation. `probeOllama()` and
  `validatePort()` were removed (superseded); `validateTarget` / `isPrivateOrLocal`
  are unchanged.
- **`worker/src/lib/discovery.js`** — `recordExposedHost` now merges `stacks[]` and
  `ports[]`. **This was a real bug fix, see below.**
- **`worker/src/lib/stats.js`** — added `by_service` tallies (`checks`/`detected`/`exposed`
  per service), surfaced in `/v1/stats`.
- **`public/`** — `index.html`, `app.js`, `style.css` render per-service cards with
  severity-coloured findings and inline remediation.
- **`wrangler.toml`** — `DEFAULT_PORT` removed (no longer read; ports live in
  `services.js`).

### New: `worker/test/` — run with `npm test`

Two suites, 42 assertions, no network egress (fake Ollama/Ray/Jupyter on loopback,
in-memory KV stub). Both green.

- `probe.test.mjs` — probe engine: detection, versions, severity, port allowlist, and
  an assertion that **every request issued was a GET** and that no
  `pull|generate|create|delete|push|chat` endpoint was ever touched.
- `worker.test.mjs` — full handler: report shape, attestation gate, private-target
  rejection, port allowlist, rate limiting (`[200,200,429,429]`), stats/hit-store
  writes, CORS.

---

## Three things you should know before merging

**1. A real concurrency bug was fixed in `recordExposedHost`.**
The hit store is keyed by IP alone (`discovery:hit:${ip}`). With three services, a
host exposing both Ollama and Jupyter would have fired two `recordExposedHost` calls
inside the same `Promise.all` — both reading the same `prev`, the second clobbering
the first's `port`/`stack`. `handleCheck` now collapses all exposed services into a
single write, and the entry carries `stacks[]`/`ports[]` alongside the original
scalar `stack`/`port` (kept for `listHits`, geo aggregates, and the discovery
pipeline, which all still read the scalars). `by_stack` now counts host+stack pairs,
so a host first seen as Ollama that later exposes Jupyter increments the Jupyter
bucket instead of being skipped. There's a test.

**2. The port field was removed from the public UI, deliberately.**
The brief's guardrail is "scope targets to HTTP(S) on the known AI ports — not a
general-purpose port prober." The old `validatePort` accepted 1–65535, which made
`/v1/check` exactly that: an attested user could probe port 22 or 3306 on any host
through Cloudflare's egress. Ports are now validated per service against
`allowedPorts` (Ollama 11434/11435, Ray 8265/8266, Jupyter 8888/8889/8890). Callers
can still pass `ports: {ollama: 11435}`; anything else gets a 400 with the allowed
list. If you want custom ports back, widen the per-service list rather than
restoring an open range.

**3. `vuln.js` stack IDs (resolved on merge).**
`ADVISORIES` previously used `jupyter_open` while the checker emits `stack: "jupyter"`.
Renamed to `jupyter` (and discovery multilane/profile IDs aligned) so tier-2 matching
works off `(stack, exposed)`.

---

## API shape

Request (all fields optional; empty body is the common path):

```json
{ "target": "host.example.com", "authorized": true,
  "services": ["ollama","ray","jupyter"], "ports": {"ollama": 11435},
  "turnstile_token": "..." }
```

Response:

```json
{ "ok": true, "mode": "own_ip", "target": "your_egress_ip",
  "checked_at": "...", "overall_severity": "critical", "any_exposed": true,
  "services": [{ "service":"ollama","label":"Ollama","port":11434,"detected":true,
    "version":"0.6.2","exposed":true,"authenticated":false,"latency_ms":41,
    "models":[{"name":"llama3.2:3b","size":null}],
    "findings":[{"id":"ollama-unauth-api","title":"...","severity":"high",
                 "detail":"...","endpoint":"/api/tags"}],
    "remediation":["..."] }],
  "guidance": "...", "limitations": "...",
  "port": 11434, "exposed": true, "auth_required": false,
  "latency_ms": 41, "models": [...], "error": null }
```

The last four-plus fields are **legacy compatibility**, mirroring the Ollama result so
the currently-deployed Pages front-end keeps working if the Worker deploys first.
Safe to drop once both sides ship — nothing in this repo reads them any more.

A legacy bare `port` in the request is mapped to `ports.ollama` and still goes
through the allowlist.

---

## Honest limitations (reflected in the UI copy)

Workers do HTTP `fetch`, not raw sockets, so a connection refused, a firewall drop,
a Cloudflare egress restriction, and a timeout are **indistinguishable** — all become
`detected: false`. A clean report therefore means "no exposed service observed from
Cloudflare's vantage point," not "you are safe." The response carries a `limitations`
string saying exactly that, and it renders under the verdict. Please don't let a
later UI pass quietly drop it.

**Fingerprints are now verified against live services** (2026-08-07) via the
local fingerprint lab, not just hand-built fakes:

| Case | Version | Result |
|---|---|---|
| Ollama | 0.32.6 | `detected`, `exposed`, `ollama-unauth-api` / high |
| Ray | 2.56.1 | `detected`, `exposed`, `ray-unauth-jobs-api` / critical |
| Jupyter, token disabled | base-notebook (Aug 2026) | `detected`, `exposed`, `jupyter-no-token-auth` / critical |
| Jupyter, token enforced | same | `detected` + `authenticated`, **not** exposed, `jupyter-reachable` / low |

Two things the live run corrected, both now encoded in `worker/test/probe.test.mjs`:

1. **`/api/status` returns no `version` field** on current `jupyter_server`. The
   old fixture invented one. Detection keys on `started`, so it still works —
   but `version` is legitimately `null` for Jupyter, not a bug.
2. **A token-enforcing Jupyter answers `403 {"message":"Forbidden"}` on
   `/api/status`.** Detection depends on the `authRejected && /jupyter|token|
   forbidden/i` fallback in `services.js`. Without that branch the tokened case
   would have gone undetected entirely. Don't remove it.

Still unverified: the tier-2 services (vLLM, Triton, Gradio, Open WebUI,
Triton, MLflow, TensorBoard) have no live-validated confirm/exposure fingerprints.

## Not done (explicitly out of v1 scope)

- **Tier 2 — version → CVE via OSV.dev**, NVD as backup. Not started. `vuln.js`
  stubs and `scripts/discovery/vuln_check.py` are yours and untouched.
- **Remaining services**: vLLM (8000 `/version` + `/v1/models`), Triton (8000/8002
  `/v2` + `/v2/models`), Gradio (7860 `/config`), Open WebUI (`/api/config`),
  MLflow (5000), TensorBoard (6006). Adding one is a single entry in `SERVICES` plus
  its ports in `allowedPorts` — the engine needs no changes.
- **CLI parity**: `src/check_ollama_exposure.py` still does Ollama only and does not
  call the Worker. Porting the same three-service recipe would keep the CLI and the
  hosted checker telling the same story.
- **Live seed merge**: the 168-exposed / 320-with-geo seed under `~/LeakyCompute/data/`
  has not been copied into this tree.
- **No commits, no deploy.** `wrangler deploy` and the Pages publish are unrun.
