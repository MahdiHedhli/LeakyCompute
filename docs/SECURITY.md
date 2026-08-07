# Security policy

## What this project is

LeakyCompute is a **defensive** research instrument:

- Public self-check uses **read-only GETs only**, one confirm + one exposure probe per service:

  | Service | Port | Confirm | Exposure check |
  |---|---|---|---|
  | Ollama | 11434 | `GET /api/version` (fallback `GET /`) | `GET /api/tags` |
  | Ray | 8265 | `GET /api/version` (fallback `GET /`) | `GET /api/jobs/` |
  | Jupyter | 8888 | `GET /api/status` (fallback `GET /`) | `GET /tree` |

  The exposure probe only runs once the service is confirmed, and nothing in the
  probe path submits a job, pulls a model, sends a prompt, or otherwise changes
  target state. We report that an endpoint answers unauthenticated requests; we
  never send one to prove impact.
- Target ports are validated against each service's known-port list, so `/v1/check`
  cannot be used as a general-purpose port prober
- Response bodies from targets are read with a 32 KB cap and redirects are never
  followed, so a hostile target cannot stream at the Worker or bounce it elsewhere
- Strict rate limits and optional Turnstile
- Private abuse logs (hashed identifiers) — **not** in git
- Gated lab for vetted GitHub users; **no** third-party chat proxy at launch

## What this project is not

- Not a mass internet scanner as a service  
- Not STOLEN COMPUTE (no random anonymous host proxy)  
- Not an exploit kit (path traversal / SSRF payloads are filtered from seed catalogs)

## Reporting

If you find a vulnerability in LeakyCompute itself (auth bypass, SSRF in our Worker, allowlist escape), open a **private** security advisory on GitHub or email the maintainer via profile contact.

Please **do not** use this project to attack third parties.

## Abuse

Override checks require explicit authorization attestation and are rate-limited + logged privately. Maintainers may revoke lab access (`access-revoked` label) and block abusive clients.
