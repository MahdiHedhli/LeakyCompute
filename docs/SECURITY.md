# Security policy & project constitution

This document is the standard every change is checked against. It is written as
**invariants** — statements that must remain true — rather than intentions, so a
diff can be verified against it by a reviewer or an agent.

If a change cannot be made without breaking an invariant, it does not ship in
that form. Amending an invariant is a deliberate, documented act
(see [Amending](#amending)), not a side effect of a feature.

---

## 0. The line

LeakyCompute measures exposed AI infrastructure **to help operators close it**.
The project's legitimacy rests on being distinguishable from the things it
studies — STOLEN COMPUTE, NadMesh, ShadowRay tooling. Those also enumerate
exposed AI endpoints. The difference is not stated intent; it is behaviour that
can be audited from the source tree.

Every invariant below exists to keep that difference auditable.

---

## 1. Probe invariants

**I-1. Every request to a third-party target is a `GET`.**
No POST, PUT, PATCH, DELETE, or any method with side effects — including
"harmless" ones. Enforced by `safeGet()` in `worker/src/lib/services.js`;
asserted in `worker/test/probe.test.mjs`.

**I-2. Probe paths are metadata, health, version, or listing endpoints only.**
Never a job submission, model pull, prompt, kernel start, file read, or any path
that makes the target *do* something. Current tier-1 set:

| Service | Port | Confirm | Exposure check |
|---|---|---|---|
| Ollama | 11434 | `GET /api/version` (fallback `GET /`) | `GET /api/tags` |
| Ray | 8265 | `GET /api/version` (fallback `GET /`) | `GET /api/jobs/` |
| Jupyter | 8888 | `GET /api/status` (fallback `GET /`) | `GET /tree` |

The off-Worker re-verification runner probes a wider set. Its paths are part of
this invariant, not an implementation detail, so they are listed here and
asserted in `governance_gates.py` (`every lane probes a reviewed metadata path`):

| Lane | Port | Probe path |
|---|---|---|
| ollama | 11434 | `/api/ps` |
| jupyter | 8888 | `/` |
| ray | 8265 | `/api/version` |
| open_webui | 8080 | `/api/config` |
| localai | 8080 | `/v1/models` |
| litellm | 4000 | `/health/liveliness` |
| vllm | 8000 | `/v1/models` |
| openai_compat_8000 / _8080 | 8000 / 8080 | `/v1/models` |
| comfyui | 8188 | `/system_stats` |
| gradio | 7860 | `/config` |
| mlflow | 5000 | `/health` |
| triton | 8000 | `/v2` |
| tensorboard | 6006 | `/data/plugins_listing` |

**Corrected 2026-08-11 — `litellm` must never probe `/health`.** On a LiteLLM
proxy that path is not metadata: it runs a live check by issuing a real
completion against every model in the operator's config, so probing it makes the
target do work and bills its owner for it — on exactly the unauthenticated
proxies the lane exists to find. It was added as `/health` and caught in
adversarial review before it ever ran. `/health/liveliness` returns a constant
and calls no model. Asserted by `the litellm lane does not spend the operator's
money`.

The general rule this cost us: **a path named "health" is not automatically
read-only.** Every new lane needs its path checked against that service's actual
implementation, not against the word in the URL.

**I-3. We report that an endpoint answers unauthenticated requests. We never
send one to prove impact.**
Demonstrating exploitability against a third party is permanently out of scope —
including when the user attests ownership, including for a write-up, including
when the payload is "safe". Impact is described in prose in the finding.

**I-4. The exposure probe runs only after the service is confirmed.**
Unconfirmed hosts receive the confirm attempts and nothing else.

**I-5. Ports are validated per service against a fixed allowlist.**
`/v1/check` must never accept an arbitrary port. This is what stops it being a
general-purpose port prober — for us, and for anyone else who finds the endpoint.
See `resolvePort()` and the allowlist table in [API.md](API.md).

**I-6. Redirects are never followed** (`redirect: "manual"`), so a target cannot
bounce a probe to a third host.

**Corrected 2026-08-11 — this had only ever been true of the Worker.** The
off-Worker runner used urllib's default opener, which follows 301/302/303/307
automatically, so a probed host could answer with a `Location:` and aim our GET
at a host that appears in no public index, at a path nobody reviewed. That makes
the project a request reflector pointed by the target, and it defeats I-22 —
which was added in the same session — from outside. The runner now uses a
no-redirect opener. Asserted by `a probed host cannot bounce the runner onto
another host`.

The general rule: **an invariant enforced in one probe path is not enforced.**
When probing moved off-Worker, every I-1…I-7 guarantee needed re-proving there,
and only some of them had been.

**I-7. Response bodies are read with a hard cap** (32 KB, `readCapped()`), so a
hostile target cannot stream unbounded data at the Worker.

**I-8. Connection failure, timeout, and filtering are reported as
`detected: false` — never as an error, never as "safe".**
A clean result always ships with the `limitations` caveat attached.

---

## 2. Authorization invariants

**I-9. The default target is the caller's own egress IP** (`CF-Connecting-IP`).
That path needs no attestation because it is inherently self-authorized.

**I-10. Any other target requires an explicit `authorized: true` attestation.**
No attestation, no scan. Refusals are logged.

**I-11. Private, reserved, loopback, link-local and CGNAT targets are refused
from the public API** — with or without attestation.

**I-12. Rate limits are enforced server-side at the Worker**, per source IP and
globally. Client-side limits are not limits.

---

## 3. Data handling invariants

**I-13. A caller's IP is never echoed back to them.** `own_ip` mode returns the
literal string `your_egress_ip`.

**Identity note — what Access actually asserts.** The lab signs in through
Cloudflare Access with GitHub as the IdP, and the assertion carries the GitHub
account's **primary email address**, not the username. There is no
`github_login` claim to read. The approval workflow records a username (that is
what an issue can carry), so an entry holds the username plus the email as an
alias, and every gate matches on all identities an assertion presents. Checking
one string is what produced a session that passed `/v1/research/me` and was
refused by every lab query — see the cross-gate test in `routes.test.mjs`.

**I-14. Raw IPs never reach a public endpoint.** They exist only in the
admin-token-gated hit store. Public aggregates are counts by country, ASN, and
stack.

**I-15. Abuse logs store hashed identifiers only** — salted, 14-day TTL, covering
both client IP and override target.

**I-16. Strings returned by a probed host are untrusted input.**
Versions, model names, page titles and error bodies are attacker-controlled in
override mode. Any client rendering them must escape them.

**I-17. Discovery seed catalogs are stripped of exploit-shaped entries**
(path traversal, metadata IPs, webhook collectors) before publication.

---

## 4. Scope invariants

**I-18. The Worker does not scan the internet.** One target per request, on
request. Bulk discovery runs off-Worker, slowly, capped.

**I-19. No mass scanning from any machine associated with this project.**
No masscan/zmap sweeps of third-party address space, at any rate, for any reason.
Local scanning means hosts and containers you own.

**I-20. No proxying of user traffic through third-party hosts.** This is the
single behaviour that defined STOLEN COMPUTE. It does not ship, in any phase.

**I-21. Discovery sources are used within their terms of service.** OSINT sources
that surface endpoints from someone's committed configuration (code search,
public notebooks) are **counted, never probed**.

---

## 4a. Which invariants are machine-checked

`npm test` enforces the following. **The rest are review-only** — that is the
honest state, and closing the gaps is tracked work, not a claim.

| Invariant | Covered by |
|---|---|
| I-1 GET only | `every request was a GET` |
| I-2 no state-changing paths | `no state-changing ollama endpoints touched`, `no ray job submission` |
| I-4 exposure after confirm | `exposure probe skipped when service not confirmed` |
| I-5 port allowlist | `rejects arbitrary port`, `rejects ray port on ollama service`, `SSH port rejected before any probe is sent`, `legacy bare port also goes through the allowlist` |
| I-8 failure ≠ error ≠ safe | `not detected, error recorded, no findings`, `limitations disclosed` |
| I-10 attestation gate | `no attestation -> 400 authorization_required`, `refusal logged for abuse review` |
| I-11 private targets refused | `private target rejected even with attestation` |
| I-12 server-side rate limits | `blocks after RL_OWN_MAX in the window`, `429 body names the scope` |
| I-13 IP never echoed | `client IP is never echoed back in any result field` |
| I-14 no raw IPs public | `exposes by_service, no raw IPs` |
| I-15 hashed abuse logs | `abuse log stores hashed target, never the raw host` |
| I-25 opt-out honoured before the probe | `NO request reached any target — skipped, not suppressed`, `exclusion beats an attested scan request for the same space`, `an ingest cannot write back a host that is excluded`, `re-filing a removal request purges again, not only the first time`, plus the `exclusions.test.mjs` parsing/matching/bound suite |
| I-2 probe paths, off-Worker | `every lane probes a reviewed metadata path`, `the litellm lane does not spend the operator's money` |
| I-6 redirects | `I-6: the probe never follows a redirect off the target` (Worker), `a probed host cannot bounce the runner onto another host` (runner) |
| I-23 attributable probes | `probes carry the agent the public page names`, `every agent this project probes under is attributable to it` |
| I-24 re-probe interval | `a re-probe inside the interval is skipped, outside it is due`, `the interval is a floor a flag cannot lower` (driven through the CLI), `a host that did not answer still lands in the probe clock` |
| I-26 expiry + minimisation | the `retention.test.mjs` suite: expiry from last contact, minimised record shape, aggregates that follow deletion down |

**Not machine-checked yet:** I-3 (no impact proof — the *probe paths* are
asserted against a reviewed list, but "we never send a request to prove impact"
is a property of every future change, not of the current table), I-7 (body cap
in the Worker is asserted; the off-Worker runner has no equivalent — see the
`triton` lane comment), I-16 (client-side escaping — verified manually against a
hostile payload, but no regression test), I-17, I-18–I-21 (process/scope
invariants that live outside the Worker).

---

## 5. Decision procedure for new capability

Before adding a service, probe path, discovery source, or data field, answer in
the PR or spec:

1. **Which invariant could this break?** If none, say so explicitly.
2. **Is every new request a read-only GET against a metadata endpoint?** (I-1, I-2)
3. **Does it widen the port allowlist?** If so, why is each new port a known AI
   service port? (I-5)
4. **Does it introduce a new class of identifier?** Hostnames, org names and
   emails are *not* equivalent to an IP in a hosting ASN — see Q-1. (I-14)
5. **Does it increase active probe volume?** Then it needs a cap, and the cap is
   documented. (I-18)
6. **Would this be indistinguishable from NadMesh if someone read only the
   network traffic?** If yes, stop.

---

## 6. Open questions — settle before shipping, not after

**Q-1. Certificate Transparency yields named organizations.**
CT-derived hostnames identify *whose* infrastructure is exposed — a materially
different disclosure posture than an anonymous hosting IP. Before the CT lane
ships: decide retention, decide whether hostnames may appear in any aggregate,
and confirm I-14 extends to them. Default if undecided: treat hostnames exactly
as raw IPs — admin-gated, never public.

**Q-2. Coordinated disclosure has no policy.**
We can identify exposed hosts and, via OSV, versions with known CVEs. There is no
documented position on whether or how operators are notified. Until there is, we
do not contact operators.

**Q-3. Published counts inherit their source's bias.**
The by-country chart is Shodan-shaped. Broaden sources or caveat the chart —
publishing it unqualified overstates what was measured. See [DISCOVERY.md](DISCOVERY.md).

**Q-4. Tunnelled exposure is structurally invisible** (ngrok, trycloudflare,
Tailscale Funnel). Published totals must say so rather than imply completeness.

---

## 7. What this project is not

- Not a mass internet scanner as a service
- Not STOLEN COMPUTE — no random anonymous host proxy, ever
- Not an exploit kit — no traversal or SSRF payloads, in code or in seed catalogs
- Not a vulnerability *prover* — we report reachability, not demonstrated impact
- Not an attack tool, and not to be used against third parties

---

## Reporting a vulnerability in LeakyCompute

Auth bypass, SSRF in our Worker, allowlist escape, admin-token handling, or any
way to make the checker probe something it should not: open a **private** GitHub
security advisory, or email the maintainer via profile contact. Please do not
open a public issue first.

## Abuse handling

Override checks require attestation, are rate-limited, and are logged privately
with hashed identifiers. Maintainers may revoke lab access (`access-revoked`
label) and block abusive clients.

## Amending

Changing an invariant requires the amendment stated in the PR description, the
reason, and the compensating control if one exists. Invariants are numbered so
they can be cited in specs, reviews and commit messages — cite `I-3`, not "the
read-only rule".
