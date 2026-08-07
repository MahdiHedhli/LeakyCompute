# Security policy

## What this project is

LeakyCompute is a **defensive** research instrument:

- Public self-check uses **safe probes only** (`GET /api/ps`)
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
