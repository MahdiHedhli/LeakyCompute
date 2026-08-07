# LeakyCompute

**DON'T PANIC // Threat Research**

Defensive research instrument for **internet-exposed AI inference** (especially unauthenticated Ollama). Inspired by the UX of [STOLEN COMPUTE](https://web.archive.org/web/20260727203031/https://stolencompute.com/) — rebuilt with a **Don't Panic cyberpunk-noir** skin, safe probes only, hard rate limits, and a **GitHub-SSO gated researcher lab**.

> Evidence first. Panic never.  
> We measure exposure. We do **not** proxy chat through strangers' GPUs.

![LeakyCompute](public/assets/logo.svg)

## What you get

| Surface | Host (free) | Audience |
|---------|-------------|---------|
| **Public pulse** | GitHub Pages (`public/`) | Anyone — dual counters + safe self-check + checklist |
| **API** | Cloudflare Worker (`worker/`) | Stats, rate-limited checks, allowlist admin, lab APIs |
| **Researcher lab** | Cloudflare Pages (`lab/`) | Allowlisted GitHub users after issue approval |
| **CLI** | `src/check_ollama_exposure.py` | Local / owned-range audits |

### Dual counters (public)

1. **Research snapshot** — filtered archive-era catalog seed (~1.8k models / ~19k host-sum after exploit-like filtering).  
2. **Live instrumented** — voluntary self-checks + researcher-owned scans only.

### Safety rails

- Probe = `GET /api/ps` only (no `/api/pull` or generate with traversal)  
- Default check target = visitor egress IP; override requires attestation  
- Strict per-IP + global rate limits; optional Turnstile  
- Private abuse logs (hashed) in Worker KV — **not** in this repo  
- Lab chat / third-party proxy **disabled at launch** (phase B later)  
- Seed catalog strips path/SSRF-shaped “models”

## Repo layout

```
public/           # GitHub Pages pulse UI
lab/              # Gated researcher UI (STOLEN COMPUTE layout, noir skin)
worker/src/       # Cloudflare Worker API
data/             # seed-models.json (filtered)
src/              # defensive Python CLI
scripts/          # seed build helpers
docs/             # DEPLOY, SECURITY, research notes
.github/          # access issue template + approve/revoke Actions
```

## Quick start (local)

```bash
# CLI — localhost only
python3 src/check_ollama_exposure.py --scan-local
python3 src/check_ollama_exposure.py --check-url http://127.0.0.1:11434

# Worker (needs wrangler + KV ids in wrangler.toml)
npx wrangler dev worker/src/index.js
# Public UI: open public/index.html via any static server, ?api=http://127.0.0.1:8787

# Lab UI offline seed preview
python3 -m http.server 5500 --directory lab
# open http://127.0.0.1:5500/?dev_user=YOUR_GITHUB&api=http://127.0.0.1:8787
# first: wrangler + approve yourself via admin API or KV
```

## Deploy

See **[docs/DEPLOY.md](docs/DEPLOY.md)** for free-tier Worker + Pages + Access + GitHub secrets.

**Researcher access flow**

1. Open issue with [Request research lab access](.github/ISSUE_TEMPLATE/request_research_access.yml)  
2. Maintainer vets GitHub profile/repos  
3. Add label **`access-approved`**  
4. Action calls Worker admin API → KV allowlist  
5. Researcher opens lab URL → Cloudflare Access → **GitHub SSO**

Revoke with label **`access-revoked`**.

## Configuration (domain-ready)

| File | Purpose |
|------|---------|
| `public/js/config.js` | `API_BASE`, Turnstile site key, lab/repo URLs |
| `lab/js/config.js` | Same for lab |
| `wrangler.toml` `[vars]` | `ALLOWED_ORIGINS`, snapshot numbers, rate limits |

When you buy a domain: point Pages/Worker custom hosts, extend `ALLOWED_ORIGINS`, update the two `config.js` files and GitHub secrets — no architectural rewrite.

## Documentation

- [Deploy](docs/DEPLOY.md)  
- [Security policy](docs/SECURITY.md)  
- [Research background](docs/research.md)  

## Seed data

```bash
python3 scripts/build_seed.py path/to/models.json -o data/seed-models.json
cp data/seed-models.json lab/data/seed-models.json
# keep SNAPSHOT_* vars in wrangler.toml in sync with seed snapshot
```

## License

MIT — see [LICENSE](LICENSE).

## Credits

- UX structure studied from archived STOLEN COMPUTE (acidvegas) via Wayback Machine  
- Brand voice: DON'T PANIC threat research / detective noir  
- Built for free Cloudflare + GitHub tiers  
