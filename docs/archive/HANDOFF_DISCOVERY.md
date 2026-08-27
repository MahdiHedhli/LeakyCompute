# Handoff prompt — discovery expansion + live fingerprint validation

*Archived implementation handoff. Paths are repository-relative so this copy
does not disclose a contributor's workstation layout.*

---

You're picking up LeakyCompute after a session that (a) validated the tier-1
checker against live services and (b) laid groundwork for expanding discovery
coverage. Nothing is committed. `npm test` is green (42 assertions, 3 suites).

**Read first:** `docs/HANDOFF_TIER1.md` (tier-1 contract + what the live run
corrected) and the new sections in `docs/DISCOVERY.md`.

## What changed

**1. Tier-1 fingerprints are now live-verified, not fake-verified.**
A local Docker lab (`scripts/discovery/local-lab/docker-compose.yml`, all ports
pinned to 127.0.0.1) ran real Ollama 0.32.6, Ray 2.56.1, and Jupyter in both
token-enforced and token-disabled configs. All four cases produce the correct
verdict. Two corrections came out of it and are now encoded in
`worker/test/probe.test.mjs`:

- `jupyter_server`'s `/api/status` returns **no `version` field**. The old test
  fixture invented one. `version: null` for Jupyter is correct behaviour.
- A token-enforcing Jupyter returns **`403 {"message":"Forbidden"}`** on
  `/api/status`. Detection depends entirely on the `authRejected && /jupyter|
  token|forbidden/i` fallback branch in `services.js`. **Do not remove it** —
  without it the tokened case goes undetected.

**2. `npm test` now preflights ports** (`worker/test/_preflight.mjs`). The test
fixtures and the fingerprint lab bind the same ports, so they can't run at once.
You'll get a readable message telling you to `docker compose ... down` instead of
a raw EADDRINUSE stack.

**3. Discovery source registry with account requirements.**
`profiles.yaml` gained a `sources:` block; `docs/DISCOVERY.md` has the same as a
table. Each source records `{account, key, friction}` so signup work can be
queued ahead of implementation. Day 1 needs **zero** signups (favicon hashes +
crt.sh). Censys/Netlas/FOFA/ZoomEye registrations should start in parallel.
Quake (needs a mainland-China mobile number) and Shadowserver (only covers
netblocks you can prove you own) are marked `deferred` — keep them off the
critical path.

**4. Favicon hash pivots — real hashes, generated locally.**
`scripts/discovery/favicon_hash.py` (stdlib-only, pure-Python MurmurHash3,
`--selftest` passes against published vectors). Verified hashes are already in
`profiles.yaml` with the version that produced them:

| Service | Shodan `http.favicon.hash:` | Version |
|---|---|---|
| Jupyter | `-895963602` | base-notebook, Aug 2026 |
| Ray | `463802404` | 2.56.1 |
| Open WebUI | `-2059688262` | 0.11.0 |
| MLflow | `-1507094812` | 3.15.1 (served at `/static-files/favicon.ico`, **not** `/favicon.ico`) |

Two confirmed negatives, recorded so nobody re-derives them:
- **Ollama serves no favicon** (404 on 0.32.6). Favicon pivots don't work; use
  `product:Ollama` and `"Ollama is running"`.
- **TensorBoard inlines its icon as a `data:` URI** (2.21.0). There's no HTTP
  resource for an engine to hash, so favicon pivots don't apply. The script now
  rejects data: URIs explicitly rather than emitting a hash that matches nothing.

## The framing that matters most

**Coverage is bounded by probe budget, not discovery.** At 0.25/sec and 48–128
hosts/run, adding six sources to one funnel changes *which* hosts get sampled,
not how many. `docs/DISCOVERY.md` now splits the pipeline into **passive census**
(free, more sources always better, should anchor published totals) and **active
verification** (capped, should be a stratified sample of the census). They're
currently fused, which is why the by-country chart silently inherits Shodan's
scan bias. Either add FOFA/ZoomEye or caveat the chart before publishing.

## Suggested next work

1. **CT lane** (`crt_sh` / `certstream`) — highest structural gain, no accounts.
   `ct_patterns` regexes are already per-lane in `profiles.yaml`. Two rules:
   a CT hit is *not* an exposure (resolve → one safe GET → then it counts), and
   CT yields **named organizations**, so decide the handling rule before turning
   it on — hostnames should never reach a public endpoint, same as raw IPs.
2. **Wire favicon queries into `run_multilane.py`.** Note its `LANES` list is
   hardcoded and does not read `profiles.yaml` — worth reconciling.
3. **Tier-2 fingerprints are still unvalidated.** vLLM, Triton, Gradio, Open
   WebUI, MLflow, TensorBoard have no live-verified confirm/exposure pair. The
   lab makes this cheap; add services to the compose and repeat the tier-1 method.
4. **Docs structure** — see the assessment at the end of `docs/DISCOVERY.md`
   and the note in `README.md`: the `/v1/check` API contract currently only
   exists inside a handoff document, which will rot. It needs a real home.

## House rules

Read-only GETs only, no state-changing calls to targets, per-service port
allowlist (not a general port prober), no mass scanning from local machines, and
**do not add Claude as a commit co-author**.
