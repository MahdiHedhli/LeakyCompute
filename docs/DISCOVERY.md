# Discovery model (passive-first, slow active)

## Severity hook (for the post)

Static host counts are weaker than: **attackers already run these exact queries at scale.**

Cite primary sources (verify at publish time):

| Theme | Direction to cite |
|--------|-------------------|
| **NadMesh** | Mid-2026 Go botnet; `ai_harvest`-style modules query Shodan for ComfyUI, Ollama, n8n, Open WebUI, Langflow, Gradio → exploit queue (cloud keys, K8s tokens, etc.) |
| **ShadowRay / 2.0** | Oligo writeups on exposed Ray dashboards and self-propagation |
| **GreyNoise** | Late-2025–early-2026 campaigns / sessions against LLM endpoints |
| **Ollama exposure** | SentinelOne/Censys-class studies (~175k / multi-country); Cisco Talos Ollama/Shodan methodology |
| **Query catalogs** | 7WaySecurity/ai_osint; AIMap-style per-service fingerprints |

**Line vs NadMesh:** LeakyCompute stops at discovery + optional **safe read-only** probes on **capped** sets. No RCE queue, no credential harvest, no self-propagation.

---

## Critical fact about the archive seed

`data/seed-models.json` lists **model names + host counts** from STOLEN COMPUTE.
It does **not** contain IP addresses.

ASN / block candidates come from:

1. **Shodan facets** (`asn`, `org`) on high-signal queries  
2. **Shodan host matches**  
3. **Prior exposed hits** in Worker KV (private)  
4. Optional **local seeds file**

Live STOLEN COMPUTE is gone (`stolencompute.com` = goodbye page; `.org` does not resolve here). Do not depend on their API.

---

## The technique worth teaching: negative-banner filters

```text
Raw open port          →  noise (everything)
Title / product hit    →  better (right software)
Minus auth chrome      →  "wide open" (what matters)
```

Example (live counts on our Shodan key, Aug 2026):

| Query | ~Total | Meaning |
|--------|-------:|---------|
| `port:8888` | **1.7M** | Noise |
| `http.title:"Jupyter" port:8888` | **~3.5k** | Jupyter-ish |
| `http.title:"Jupyter" port:8888 -http.html:"token"` | **~380** | Likely unauth notebooks |
| `http.title:"Jupyter" port:8888 -http.html:"login"` | **~471** | Similar idea |

**Indexed vs actually unauthenticated** is the number that should anchor the post.

Same idea for other stacks: `-http.html:"login"`, `-http.html:"Sign in"`, `-http.html:"Unauthorized"`.

---

## Flagship three (highest impact stories)

### 1) Ollama — port 11434

```
product:Ollama
port:11434 "Ollama"
"Ollama is running"
```

| Query | ~Total (our key) |
|--------|-----------------:|
| `product:Ollama` | **~12.2k** |
| `"Ollama is running"` | **~835** |
| `port:11434 "Ollama"` | **~47** |

Prefer **`product:Ollama`** for seeding. Banner-only under-indexes; bare `port:11434` over-indexes (~183k).

Safe probe: `GET /api/ps` or `GET /api/tags` only.

### 2) Ray — port 8265

```
port:8265
```

| Query | ~Total |
|--------|-------:|
| `port:8265` | **~392** |

Then fingerprint `/api/version` or dashboard HTML. Exposure story: reachable dashboard / Jobs API without treating “no CVE in scanner” as safe (open-ports-checker pattern).

### 3) Jupyter — unauth filter (the clincher)

```
http.title:"Jupyter" port:8888 -http.html:"token"
```

Safe probe: `GET /` only (no kernel exec).

---

## Broader stack (each its own lane)

| Service | Preferred query | Port | Safe probe |
|---------|-----------------|------|------------|
| Open WebUI | `http.title:"Open WebUI"` | varies | `GET /` |
| ComfyUI | `http.title:"ComfyUI"` | 8188 | `GET /system_stats` |
| Gradio | `http.title:"Gradio"` | 7860 | `GET /` |
| LocalAI | `http.html:"LocalAI"` | 8080 | `GET /v1/models` |
| LiteLLM | `http.html:"LiteLLM"` | 4000 | `GET /health` |
| vLLM | `http.html:"vLLM"` or `port:8000 http.html:"/v1/models"` | 8000 | `GET /v1/models` |
| OpenAI-compat | `http.html:"/v1/models"` | 8000/8080 | `GET /v1/models` |
| MLflow | `http.title:"MLflow"` | 5000 | `GET /` |
| TensorBoard | `http.title:"TensorBoard"` | 6006 | `GET /` |

Machine-readable profiles: [`scripts/discovery/profiles.yaml`](../scripts/discovery/profiles.yaml).

**Do not** seed primarily from bare `port:8000/8080/5000/8888` — millions of non-AI services.

---

## Pipeline (implementation)

```text
Shodan facets → top ASNs (Hetzner, Contabo, OVH, AWS, …)
       │
       ├─► limited hosts per ASN (e.g. 8 each)
Prior hits ──► re-check known exposed IPs
       │
       ▼
Optional /29–/30 neighborhood expand (never wider than /28)
       │
       ▼
SLOW stack-aware GET probes on YOUR machine
  default ~0.2–0.25/sec, 1 worker, max 48–64 hosts/run
       │
       ▼
Worker ingest (batches ≤150, ≤10/hour) → private hits + public counters
```

**Cloudflare Worker does not scan the internet.**

---

## Rate limits (free-tier / anti-block)

| Layer | Limit |
|--------|--------|
| Active probe default | **0.25/sec**, **1 worker** |
| Hard ceiling | max **1.0/sec**, max **2** workers, max **128** hosts/run |
| Neighborhood | prefix **≥ /28**; prefer **/30** |
| Hosts per ASN | default **8**, max **25** |
| Worker public check | 3 / 15m own-IP; 1 / 15m override; **800**/day global |
| Worker ingest | **≤150**/request, **10**/hour |

---

## CLI

```bash
export SHODAN_API_KEY=...
export LEAKY_API_BASE=https://leakycompute-api.mhedhli.workers.dev
export LEAKY_ADMIN_TOKEN=...

# Passive ASN report (Ollama lane)
python3 scripts/discovery/discover.py --asn-report \
  --shodan-query 'product:Ollama'

# Jupyter unauth-style query (passive count + ASN when using --asn-report)
python3 scripts/discovery/discover.py --asn-report \
  --shodan-query 'http.title:"Jupyter" port:8888 -http.html:"token"'

# Slow Ollama calibration (active)
python3 scripts/discovery/discover.py \
  --shodan-query 'product:Ollama' \
  --from-top-asns 10 --hosts-per-asn 8 \
  --max-total 48 --rate 0.2 --workers 1 \
  --ingest --output data/discovery-last-run.json
```

---

## Suggested post structure (defense)

1. **Hook:** attackers already run these queries (NadMesh / ShadowRay / GreyNoise)  
2. **Technique:** negative-banner filters (Jupyter table)  
3. **Flagship three:** Ollama / Ray / Jupyter  
4. **STOLEN COMPUTE:** catalog + proxy pattern; site now closed  
5. **LeakyCompute:** measure without becoming the bot  
6. **Hardening:** bind localhost, reverse proxy + auth, SG/NACL, input sanitization, open-ports-checker for Ray  

---

## Resources (starting points)

- 7WaySecurity/ai_osint — query catalog  
- Cisco Talos — Ollama / Shodan methodology  
- Oligo — ShadowRay writeups  
- AIMap / Help Net Security — multi-stack fingerprints  
- Anyscale open-ports-checker pattern — Ray exposure class  

Verify URLs and numbers at publish time; Shodan totals move daily.
