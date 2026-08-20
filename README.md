<div align="center">

<img src="public/assets/logo.svg" width="96" height="96" alt="LeakyCompute" />

# LeakyCompute

**DON'T PANIC // Threat Research**

*Is your AI inference server answering the whole internet?*

### → **[Check your own IP — no signup, no input](https://mahdihedhli.github.io/LeakyCompute/)** ←

[![License: MIT](https://img.shields.io/badge/License-MIT-f5c542.svg)](LICENSE)
[![Probes](https://img.shields.io/badge/probes-read--only%20GET-5ce1ff.svg)](docs/SECURITY.md)
[![Opt out](https://img.shields.io/badge/opt%20out-honoured%20on%20receipt-ff6b6b.svg)](https://github.com/MahdiHedhli/LeakyCompute/issues/new?template=request_removal.yml)

</div>

---

Thousands of Ollama, Ray, and Jupyter servers are reachable from the public
internet with no authentication at all. Anyone who finds one can run inference on
someone else's GPU, read their models, and — on Ray and Jupyter — execute code.

LeakyCompute measures that exposure **so operators can close it**. Visit the
checker and it tells you whether *your* address is answering, and exactly how to
stop it. Nothing is typed in; the default target is the address you connected
from, which is why the common path needs no permission from anyone.

> **Evidence first. Panic never.**<br>
> We measure exposure so operators can close it.

## Try it

| | |
|---|---|
| 🔎 **[Public checker](https://mahdihedhli.github.io/LeakyCompute/)** | Scans your own egress IP for Ollama, Ray and Jupyter. No input, no account. |
| 📄 **[About our scanning](https://mahdihedhli.github.io/LeakyCompute/scanning.html)** | Found us in your logs? Exactly what we send, and a one-click opt-out. |
| 🔬 **[Researcher lab](https://leakycompute-lab.pages.dev)** | Corpus browser and exposure maps. GitHub SSO, [approval required](https://github.com/MahdiHedhli/LeakyCompute/issues/new?template=request_research_access.yml). |
| ⚙️ **[API](https://leakycompute-api.mhedhli.workers.dev/v1/health)** | `/v1/*` — see the [contract](docs/API.md). |

## How a probe gets permission

The interesting part of this project is not the scanner. It's what stands
between a candidate host and a packet. Four gates, all of them ahead of the
dry-run branch, so the plan a run writes down is the plan it executes:

```
  candidate host
        │
        ▼
  ┌───────────────┐   I-22  did a public index already list this host,
  │  PROVENANCE   │         or did its owner ask us to check it?
  └───────┬───────┘         we never discover a host by probing
          ▼
  ┌───────────────┐   I-25  did anyone ask to be left alone?
  │  EXCLUSIONS   │         fails closed — no list, no probe
  └───────┬───────┘
          ▼
  ┌───────────────┐   I-24  probed within the last 14 days?
  │   INTERVAL    │         fails closed — no clock, no probe
  └───────┬───────┘
          ▼
  ┌───────────────┐   I-24  global rate ceiling, plus per-/24
  │  RATE + PORT  │   I-5   and per-ASN limits; port must be on
  └───────┬───────┘         that service's allowlist
          ▼
   read-only GET   ← the only thing we ever send
```

**We never discover a host by probing.** Every address we contact was already
published in a public index, or its owner asked us to look. That single rule is
what separates this from the tooling it studies, and it holds whether the corpus
is 300 hosts or 300,000.

## What it checks

Confirm the service, then run one read-only exposure check. Never a job
submission, model pull, prompt, kernel start, or file read.

| Service | Port | Confirm | Exposure check |
|---|---|---|---|
| **Ollama** | 11434 | `GET /api/version` | `GET /api/tags` |
| **Ray** | 8265 | `GET /api/version` | `GET /api/jobs/` |
| **Jupyter** | 8888 | `GET /api/status` | `GET /tree` |

Background re-verification covers a wider set — vLLM, Triton, Open WebUI,
LocalAI, LiteLLM, ComfyUI, MLflow, TensorBoard, Gradio — every probe path listed
and justified under invariant I-2 in [SECURITY.md](docs/SECURITY.md).

Ray is flagged on **configuration, not version**: CVE-2023-48022 is disputed
because the vendor considers missing auth intended, so upgrading will not fix it.

## Three numbers, never summed

The public page shows three separate measurements with different provenance,
because collapsing them into one would be the easiest lie to tell:

| | |
|---|---|
| **Archive snapshot** | What a Wayback-era catalog listed. Counted, never probed by us. |
| **Indexed, observed** | Hosts in public index records today. Counted, not probed. |
| **Re-verified** | Hosts that answered a read-only GET *from us*, inside the re-probe window. |

The third number is the only one we stand behind directly, and it is the
smallest. That gap is the honest finding, not a shortfall to engineer away.

## Safety rails

Every rule below is a numbered invariant in
**[docs/SECURITY.md](docs/SECURITY.md)**, the document each change is reviewed
against. Most are enforced by `npm test` rather than by good intentions.

- **Read-only `GET` only** — never `/api/pull`, `/api/generate`, a Ray job, or a traversal payload
- **We report that an endpoint answers unauthenticated requests. We never send one to prove impact**
- **Ports validated per service** against a fixed allowlist — not a general port prober
- **Redirects never followed**, so a target cannot bounce a probe to another host
- **Default target is your own egress IP**; any other target requires an ownership attestation
- **Opt-out honoured on receipt**, reviewed afterwards, and never expires
- **Records expire 180 days after last contact** — a host that goes quiet ages out
- **Raw addresses never reach a public endpoint** — public figures are counts by country, ASN and stack
- **The lab reads our stored corpus only** — it never sends a request to a discovered host

## Opt out

Don't want us touching your address space? **[Open a removal
request](https://github.com/MahdiHedhli/LeakyCompute/issues/new?template=request_removal.yml)**
— it is applied when we receive it, not when we finish reviewing it. No
justification required, and it never expires. Email works equally well if you'd
rather not use GitHub; needing an account in order to be left alone would not be
an opt-out.

## Scanning a range you own

The web checker answers for **one address at a time** — the one you connected
from, or a single host you attest to owning. That is deliberate: it probes on
our infrastructure, so it is rate limited, and a rate limit is the wrong tool
for someone who needs to check a hundred machines.

If you own more than one, run the checker yourself. It executes on your network,
answers immediately, has no rate limit, and never asks us for permission to look
at your own infrastructure.

```bash
git clone https://github.com/MahdiHedhli/LeakyCompute
cd LeakyCompute

# a single host
python3 src/check_ollama_exposure.py --check-url http://10.0.0.5:11434

# everything listening on this machine
python3 src/check_ollama_exposure.py --scan-local

# a range you own — the attestation flag is required, not decorative
python3 src/check_ollama_exposure.py \
  --scan-cidr 203.0.113.0/24 --i-own-this-range \
  --max-hosts 256 --output-json exposure.json
```

Stdlib Python 3 only — no install step, nothing to trust beyond a file you can
read in full before running it.

**Only scan address space you control.** `--i-own-this-range` exists to make that
a deliberate act rather than a default. Pointing this at someone else's network
is unauthorised scanning wherever you are, and it is not what this tool is for.

Results stay on your machine. Nothing is sent to us — which also means a clean
result here does not add to the public counters, and is not meant to.

## Repo layout

```
public/            # GitHub Pages checker + /scanning disclosure page
lab/               # Access-gated researcher UI (corpus, maps, validation)
worker/src/        # Cloudflare Worker API
worker/test/       # the invariant suite — npm test
scripts/discovery/ # off-Worker re-verification runner + gates
src/               # defensive Python CLI
docs/              # constitution, API contract, discovery model, specs
.github/           # access + removal templates and their Actions
```

## Local development

```bash
npm test                                  # the invariant suite

# CLI — localhost only
python3 src/check_ollama_exposure.py --scan-local

# Worker + public checker
npx wrangler dev
# then open public/index.html with ?api=http://127.0.0.1:8787

# Researcher lab against a local Worker
python3 -m http.server 5500 --directory lab
# http://127.0.0.1:5500/?api=http://127.0.0.1:8787&dev_user=YOUR_GITHUB
# needs ENVIRONMENT=development and an allowlist entry for that login
```

Discovery runs **on your machine**, never inside the Worker:

```bash
export SHODAN_API_KEY=... LEAKY_API_BASE=... LEAKY_ADMIN_TOKEN=...

python3 scripts/discovery/run_multilane.py --self-test   # gates only, no packets
python3 scripts/discovery/run_multilane.py --dry-run     # passive pull, no packets
python3 scripts/discovery/run_multilane.py --ingest      # all four gates live
```

`--ingest` refuses to run if it cannot read the exclusion list or the probe
clock. That is the design, not a bug: an opt-out that stops being consulted when
the network hiccups is not an opt-out.

## Documentation

- **[Security policy & constitution](docs/SECURITY.md)** — the numbered invariants, and which are machine-checked. Read this before adding any probe or source.
- [API reference](docs/API.md) — the `/v1/*` contract, findings, severities, rate limits
- [Re-verification & disclosure spec](docs/specs/001-reverification-and-disclosure.md) — the corpus expansion plan and the disclosure policy
- [Discovery model](docs/DISCOVERY.md) — passive lanes, source registry, local fingerprint lab
- [Deploy](docs/DEPLOY.md) · [Research background](docs/research.md)

## Reporting a problem

If you can make this checker probe something it should not — auth bypass, SSRF
in the Worker, allowlist escape — that is a security issue in *our* software.
Open a private GitHub security advisory rather than a public issue.

## License

MIT — see [LICENSE](LICENSE).

<div align="center">
<sub>UX structure studied from archived STOLEN COMPUTE via the Wayback Machine ·
Brand voice: DON'T PANIC threat research · Built on free Cloudflare + GitHub tiers</sub>
</div>
