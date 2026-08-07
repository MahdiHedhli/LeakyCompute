# Discovery model (passive-first, slow active)

## Critical fact about the archive seed

`data/seed-models.json` lists **model names + host counts** from STOLEN COMPUTE’s catalog.
It does **not** contain IP addresses.

So we **cannot** ASN-map “seed hosts” directly from that file.

ASN / hosting-provider block candidates come from:

1. **Shodan facets** (`asn`, `org`) on Ollama-like queries  
2. **Shodan host matches** (each result includes ASN/org)  
3. **Prior exposed hits** stored privately after live probes  
4. Optional **local seeds file** you maintain  

Then we only **actively** re-probe small, capped sets — slowly.

## Pipeline

```text
Shodan facets → top ASNs (Hetzner, DigitalOcean, AWS, Contabo, …)
       │
       ├─► limited hosts per ASN (passive pull, e.g. 8 each)
Prior hits ──► re-check known exposed IPs
       │
       ▼
Optional /29–/30 neighborhood expand (never wider than /28)
       │
       ▼
SLOW active probe on YOUR machine: GET /api/ps only
  default ~0.25 probes/sec, 1 worker, max 48 hosts/run
       │
       ▼
Worker ingest (batches ≤150, ≤10 batches/hour) → private hits + public counters
```

**Cloudflare Worker does not scan the internet.**  
It only: voluntary self-checks, private hit storage, aggregate stats, allowlist.

## Rate limits (free-tier friendly)

| Layer | Limit |
|--------|--------|
| Active probe default | **0.25/sec** (1 every 4s), **1 worker** |
| Hard code ceiling | max **1.0/sec**, max **2** workers, max **128** hosts/run |
| Neighborhood expand | prefix **≥ /28** only; default expand **4** hosts/seed |
| Hosts per ASN pull | default **8**, hard max **25** |
| Worker public self-check | 3 / 15 min, 12 / day (own IP); 1 / 15 min override |
| Worker global checks | **800 / day** |
| Worker discovery ingest | **≤150** results/request, **10** requests/hour |

## CLI

```bash
export SHODAN_API_KEY=...
export LEAKY_API_BASE=https://leakycompute-api.mhedhli.workers.dev
export LEAKY_ADMIN_TOKEN=...   # ADMIN_SYNC_TOKEN from .secrets.local.json

# 1) Passive: which hosting ASNs dominate Ollama exposure?
python3 scripts/discovery/discover.py --asn-report \
  --shodan-query 'port:11434 "Ollama is running"'
# writes data/asn-candidates.json

# 2) Dry-run: seed from top hosting ASNs + prior hits
python3 scripts/discovery/discover.py \
  --from-top-asns 12 --hosts-per-asn 8 \
  --from-prior \
  --max-total 48 \
  --dry-run

# 3) Slow live run (recommended)
python3 scripts/discovery/discover.py \
  --from-top-asns 10 --hosts-per-asn 8 \
  --from-prior \
  --expand-prefix 30 --max-expand-per-seed 4 \
  --max-total 48 --rate 0.2 --workers 1 \
  --ingest --output data/discovery-last-run.json
```

## Why ASN seeding helps

Providers that show up a lot in Shodan for port 11434 are where misconfigured Ollama clusters concentrate. Pulling **a few** hosts per ASN (not the whole ASN space) gives high-yield candidates without a global scan.

Neighborhood expand (`/30` or `/29` around a confirmed hit) catches adjacent VMs on the same rack/subnet that often share the same bad firewall template.

## Cadence suggestion

| Cadence | Action |
|---------|--------|
| Weekly | `--asn-report` + refresh top ASN host pulls |
| 2–3× week | `--from-prior` only, `--rate 0.2`, no expand |
| Occasional | `--expand-prefix 30` on recent hits only |

## Guardrails

- No path-traversal / SSRF payloads  
- No full-ASN sweeps  
- No Worker-side mass scan  
- Public stats never expose raw IPs  
