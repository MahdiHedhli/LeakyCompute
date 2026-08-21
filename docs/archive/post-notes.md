# Archived: publication notes

Cut from `docs/DISCOVERY.md` on 2026-08-21. This is write-up scaffolding — a hook,
a suggested narrative order, and sources to cite — not a description of what the
system does. It was mixed into the discovery model doc, where a reader looking for
the passive lane design had to step around it.

Nothing here is authoritative. The citations were collected early and are marked
"verify at publish time" for a reason: several are secondhand characterisations of
other people's research, and the host counts in them move daily. Check every one
against its primary source before it goes anywhere public.

The narrative order in particular predates the three-number framing and the four
gates, which are now the more defensible spine for a write-up.

---

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
