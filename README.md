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

- Every probe is a **read-only `GET`** against a version / health / listing endpoint —
  never `/api/pull`, `/api/generate`, a Ray job submission, or a traversal payload
- Tier-1 coverage: **Ollama** (11434), **Ray** (8265), **Jupyter** (8888)
- Ports are validated per service against a known-AI-port list — not a general port prober
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
docs/             # constitution, API contract, discovery model, deploy
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

- [Security policy & constitution](docs/SECURITY.md) — numbered invariants every change is checked against; read before adding any probe or source
- [API reference](docs/API.md) — the `/v1/*` contract, findings, severities, rate limits
- [Discovery model](docs/DISCOVERY.md) — census vs active lanes, source registry + account requirements, local fingerprint lab
- [Deploy](docs/DEPLOY.md)  
- [Research background](docs/research.md)  
- [Tier-1 checker handoff](docs/HANDOFF_TIER1.md) · [Discovery handoff](docs/HANDOFF_DISCOVERY.md) — *session artifacts, not durable docs*

## Seed data

```bash
python3 scripts/build_seed.py path/to/models.json -o data/seed-models.json
cp data/seed-models.json lab/data/seed-models.json
# keep SNAPSHOT_* vars in wrangler.toml in sync with seed snapshot
```

**Note:** the archive seed is **model names + counts only** (no IPs). ASN/hosting-provider
candidates for active re-probes come from **Shodan facets** and prior hits — see [docs/DISCOVERY.md](docs/DISCOVERY.md).

## Discovery (passive Shodan → slow re-probe)

Active scanning runs **on your machine**, not inside the free Worker:

```bash
export SHODAN_API_KEY=...
export LEAKY_ADMIN_TOKEN=...   # Worker ADMIN_SYNC_TOKEN

# Top hosting ASNs for Ollama-like exposure (passive)
python3 scripts/discovery/discover.py --asn-report

# Slow capped run: top ASNs + prior hits + optional /30 neighbors
python3 scripts/discovery/discover.py \
  --from-top-asns 10 --hosts-per-asn 8 \
  --from-prior --expand-prefix 30 --max-expand-per-seed 4 \
  --max-total 48 --rate 0.2 --workers 1 \
  --ingest
```

Defaults are intentionally slow (≈1 probe / 4–5s) to stay polite and free-tier safe.

## License

MIT — see [LICENSE](LICENSE).

## Credits

- UX structure studied from archived STOLEN COMPUTE (acidvegas) via Wayback Machine  
- Brand voice: DON'T PANIC threat research / detective noir  
- Built for free Cloudflare + GitHub tiers  
