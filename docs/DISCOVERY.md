# Discovery model (passive-first, slow active)

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

## Flagship three

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

## Coverage is probe-bound, not discovery-bound

Read this before adding any source.

At 0.25/sec, 1 worker, 48–128 hosts/run, active verification tops out around a
few hundred hosts/day. Pouring six more discovery sources into that funnel does
not increase coverage — it changes *which* hosts get sampled. Split the pipeline
and the numbers stay honest:

| Lane | Cost | Rule |
|---|---|---|
| **Passive census** — counts, facets, candidate hostnames | zero probes | More sources is strictly better. Anchor published totals here. |
| **Active verification** — slow safe GETs | capped | Stratified sample *of* the census, not "whatever the query returned first". |

Today these are fused, which means the by-country chart silently inherits
Shodan's scan bias. Either add non-Western sources (below) or caveat the chart.

---

## Source registry — what needs an account

Machine-readable copy lives in [`profiles.yaml`](../scripts/discovery/profiles.yaml)
under `sources:`. Quotas and terms move; **verify at signup**, and check each
provider's ToS on automated querying — several are stricter than Shodan's.

| Source | Account | Key | Friction | Buys us |
|---|---|---|---|---|
| Shodan | ✅ have | `SHODAN_API_KEY` | — | current pipeline |
| **crt.sh** | ❌ none | none | **none** | reverse-proxied-on-443 population |
| **certstream** | ❌ none | none | **none** | real-time CT feed |
| **Common Crawl** | ❌ none | none | **none** | body-level fingerprints |
| Censys | ✅ | id+secret / platform token | low | independent second census |
| Netlas | ✅ | `NETLAS_API_KEY` | low | full-body search, odd ports |
| GreyNoise | ✅ | `GREYNOISE_API_KEY` | low | who is *already* scanning these ports |
| FOFA | ✅ | email + key | medium | APAC/CN coverage (fixes geo bias) |
| ZoomEye | ✅ | `ZOOMEYE_API_KEY` | medium | APAC coverage |
| Quake | ✅ | key | **high** | ⚠ signup has required a mainland-China mobile number — keep off the critical path |
| Shadowserver | ✅ | n/a | **high** | ⚠ free reports **only for netblocks you can prove you own** — not a third-party discovery source; verification takes days |

**Suggested queue.** Day 1 needs no signups at all: favicon hashes + crt.sh.
Start the Censys/Netlas/FOFA registrations in parallel on day 1 so the keys have
landed by the time the lanes are written.

---

## Favicon hash pivots

Port- and title-anchored queries miss anything behind a reverse proxy on 443, on
a non-standard port, or with a localized page title. Favicon hashes match the
served icon bytes and ignore all three.

Engines disagree on format: **Shodan** uses mmh3 of the base64 encoding
(`http.favicon.hash:<signed int>`), **Censys** uses md5.
[`favicon_hash.py`](../scripts/discovery/favicon_hash.py) emits both, stdlib-only:

```bash
python3 scripts/discovery/favicon_hash.py --selftest
python3 scripts/discovery/favicon_hash.py --yaml \
    jupyter=http://127.0.0.1:8888 comfyui=http://127.0.0.1:8188
```

**Generate hashes from a version you ran yourself — never copy them from blog
posts.** Icons change between releases, and a stale hash returns zero results,
which reads like "no exposure" rather than "wrong query".

Best candidates: Jupyter, Gradio, ComfyUI, Open WebUI, MLflow, TensorBoard.
Ollama serves no favicon by default, so expect a null there — that is a result,
not a failure.

---

## Certificate Transparency

The largest structural blind spot. Plenty of serious deployments sit behind
nginx/Caddy on 443 as `ollama.example.com` or `jupyter.corp.io` — TLS-terminated,
invisible to `port:11434`, and frequently *still* unauthenticated because the
operator assumed the proxy was the auth. CT finds a different population than
every query above.

Free, no key. Backfill from crt.sh, then stay current on certstream. Hostname
patterns live per-lane in `profiles.yaml` as `ct_patterns`.

**Two things that make this different from IP-based discovery:**

1. **CT yields named organizations, not anonymous hosting IPs.** That is a
   materially different disclosure posture. Decide the handling rule *before*
   turning the lane on — at minimum, hostnames should never reach a public
   endpoint, same as raw IPs today.
2. **A CT hit is not an exposure.** The cert proves the name existed, nothing
   more. Resolve → single safe GET → only then does it count.

---

## Known blind spot: tunnelled instances

ngrok, `*.trycloudflare.com`, localtunnel, Tailscale Funnel. A large share of
hobbyist Ollama/ComfyUI exposure is tunnelled, which means **zero** port-scan
visibility. Cloudflare quick tunnels use a wildcard cert, so CT misses them too.

Only partially addressable. Say so in the post — "the population we can measure
systematically excludes the fastest-growing exposure vector" is honest, and
better than silently undercounting.

---

## OSINT lanes — count, never probe

GitHub/GitLab code search, public Colab notebooks and HuggingFace Space configs
leak hardcoded `OLLAMA_HOST=http://x.x.x.x:11434` and tunnel URLs constantly.
Common Crawl's index is searchable for Gradio pages and `/v1/models` responses.

**Count these; do not probe them.** The provenance is someone's committed
config, not a host we have any standing to touch.

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

## Local work — no accounts, no third-party traffic

Everything here runs on your own machine against containers you control. It is
the right day-1 work: it unblocks the favicon lane, and it closes the gap that
the tier-1 fingerprints were only ever validated against hand-built fakes.

```bash
docker compose -f scripts/discovery/local-lab/docker-compose.yml up -d
docker compose -f scripts/discovery/local-lab/docker-compose.yml ps
```

The lab pins **every** port to `127.0.0.1`. Confirm before going further — some
of these images are unauthenticated by design, and a `0.0.0.0` binding would add
your own machine to the population this project measures.

**1. Generate favicon hashes** (unblocks the highest-yield search lane):

```bash
python3 scripts/discovery/favicon_hash.py --yaml \
    jupyter=http://127.0.0.1:8888 openwebui=http://127.0.0.1:3000 \
    mlflow=http://127.0.0.1:5000 tensorboard=http://127.0.0.1:6006
```

Paste the output into the matching `favicon:` block in `profiles.yaml`.

**2. Validate tier-1 fingerprints against real services.** `worker/test/` proves
the engine's *logic* against fakes; it does not prove the *fingerprints* match
real responses. Point `wrangler dev` at the lab and diff:

- `jupyter-open` (8888) must come back `exposed: true`, finding `jupyter-no-token-auth`
- `jupyter-token` (8889) must come back `detected: true, authenticated: true` — **not** exposed
- Confirm whether `/api/status` answers unauthenticated on your `jupyter_server`
  version; our confirm step leans on it, with `GET /` as fallback
- `ray` (8265) should yield `ray_version` and an empty `/api/jobs/` array

A false "clean" here is the worst failure mode the checker has — someone
concludes they're fine when they aren't.

**3. Build the OSV version matrix.** Pull several Ollama tags, record what
`/api/version` actually returns, and confirm the tier-2 OSV lookups behave
sanely across them (including the no-known-vulns case).

**4. CT backfill** needs no containers and no accounts — start collecting
`ct_patterns` matches from crt.sh into a local candidate file today. It is pure
census work, so it costs no probe budget.

### What not to do locally

Do **not** point masscan/zmap or any mass scanner at the internet from your
connection to build seeds. That is the exact line this project draws against
NadMesh, it would contradict every claim in `docs/SECURITY.md`, and it is the
kind of traffic that gets a residential connection null-routed.

Local scanning means **your own hosts and containers**. The existing
`--scan-local` mode in the CLI and your own LAN are fair game; third-party
address space is not, at any rate.

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
| Active probing | **Suspended** pending durable pre-probe leases |
| Hosted public check | **Suspended**; use the local defensive CLI |
| Neighborhood | prefix **≥ /28**; prefer **/30** |
| Hosts per ASN | default **8**, max **25** |
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

# Governance plan only — active probing is suspended until every attempt is
# durably recorded before the packet is sent.
python3 scripts/discovery/run_multilane.py --dry-run \
  --output data/discovery-multilane.json
```
