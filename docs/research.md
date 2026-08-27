# Research background

## STOLEN COMPUTE

[STOLEN COMPUTE](https://web.archive.org/web/20260727203031/https://stolencompute.com/) (acidvegas) indexed unauthenticated Ollama/vLLM endpoints and proxied chat through random anonymous hosts. Client JS (`utils.js`) exposed `/api/models`, `/api/session`, `/api/chat`, `/api/reroll`, `/api/stats`.

Archived model catalogs mixed **legitimate model names** with **exploit-shaped “models”** (path traversal, IMDS SSRF, webhook probes).

## LeakyCompute stance

We reuse the **UX pattern** (sidebar catalog, counters, stats modal) for **defense and measurement**:

| STOLEN COMPUTE | LeakyCompute |
|----------------|--------------|
| Pirate / “free AI” | DON'T PANIC cyberpunk noir |
| Random third-party host pool | Corpus we re-verified ourselves, with provenance |
| Weaponized model names | Filtered out of seed; safe `/api/ps` only |
| Opaque host pool | Three counters, never summed: archive snapshot, indexed today, re-verified by us |

## Seed methodology

1. Load Wayback-derived `/api/models` dump(s)  
2. Drop exploit-like names (`../`, metadata IPs, webhook hosts, etc.)  
3. Publish as `data/seed-models.json` with `validated: false`  
4. Promote to validated when live authorized probes confirm  
5. Remove seed rows that never validate  

Raw archive artifacts are intentionally kept outside this public repository.
