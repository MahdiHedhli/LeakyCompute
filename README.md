# Leaky Compute

**Leaky Compute** is a research project that provides a simple way for anyone to test whether their Ollama deployment is exposed to the public Internet, and a private Cloudflare‑based sandbox where vetted researchers can run full‑scale scans and publish aggregated statistics.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation & Local Testing](#installation--local-testing)
- [Deploying the Private Cloudflare Sandbox](#deploying-the-private-cloudflare-sandbox)
- [Deploying the Public UI (GitHub Pages)](#deploying-the-public-ui-github-pages)
- [Defensive Checklist](#defensive-checklist)
- [License](#license)

## Overview
The project consists of three main components:

1. **Public “self‑check” UI** – a static web page (hosted on GitHub Pages) that lets any user enter an IP address or CIDR and instantly see whether their Ollama instance is exposed. The UI calls a Cloudflare Worker that performs the actual check via direct HTTP request or via the MCP browser‑bridge (optional).

2. **Private research sandbox** – a Cloudflare Worker (protected by Cloudflare Access) that can run bulk scans over CIDR blocks owned by vetted researchers, store results in a private KV namespace, and expose aggregated statistics via a `/stats` endpoint.

3. **GitHub Action** – a scheduled GitHub Action that reads the aggregated statistics from the private worker, converts them to a markdown file, and commits the file to a dedicated *stats* repository. The public Leaky Compute site can render this markdown to show live counts.

## Prerequisites
- **Git** and **Node.js (>=18)** installed locally.
- **Cloudflare account** with Access enabled (for the private sandbox).
- **Ollama token** (if your Ollama instance requires authentication).
- **MCP binary** (optional, for the MCP‑enabled check).

## Installation & Local Testing
1. Clone the repository:
   ```bash
   git clone https://github.com/MahdiHedhli/LeakyCompute.git
   cd LeakyCompute
   ```

2. Create a Python virtual environment (optional but recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Verify the script works (direct request, no MCP):
   ```bash
   python src/check_ollama_exposure.py --help
   ```

5. (Optional) Install the MCP binary if you want to use the MCP path:
   ```bash
   git clone https://github.com/mahdihedhli/browserbridge.git
   cd browserbridge
   npm ci
   npm run build   # produces ./mcp
   sudo mv mcp /usr/local/bin/mcp   # or adjust PATH as needed
   ```

6. Run a quick test on localhost (assuming Ollama is listening on 127.0.0.1:11434):
   ```bash
   python src/check_ollama_exposure.py --scan-cidr 127.0.0.1/32
   ```

## Deploying the Private Cloudflare Sandbox
1. **Create a Cloudflare Account** and enable **Cloudflare Access** (requires an identity provider such as Azure AD, Google Workspace, etc.).
2. **Create a KV namespace**:
   ```bash
   wrangler kv:namespace create research_exposure
   ```
3. **Bind the KV namespace** to the worker (edit `wrangler.toml`):
   ```toml
   [[kv_namespaces]]
   binding = "research_exposure"
   id = "YOUR_KV_ID"
   ```
4. **Add the Ollama token as a secret**:
   ```bash
   wrangler secret put OLLAMA_TOKEN
   # paste the token and press Enter
   ```
5. **Deploy the worker** (the code lives in `private/worker.js` and `private/stats.js`):
   ```bash
   wrangler deploy
   ```
   The deployment will give you a URL such as `https://<worker-subdomain>.workers.dev`.

6. **Configure Cloudflare Access**:
   - In the Cloudflare dashboard, go to **Access → Applications**.
   - Create a new application for the worker subdomain.
   - Add the “research‑team” group (or any group that should have access) as an allowed principal.
   - Ensure the application is set to **Require Sign‑In**.

7. **Test the endpoints**:
   - Single IP check: `https://<worker-subdomain>.workers.dev/check?ip=127.0.0.1`
   - Bulk scan (POST):
     ```json
     {
       "cidrs": ["10.0.0.0/8"]
     }
     ```
   - Stats (aggregated counts):
     `https://<worker-subdomain>.workers.dev/stats`

## Deploying the Public UI (GitHub Pages)
1. The public UI lives in the `public/` directory.
2. Push the folder to a GitHub repository (the same repo works). GitHub Pages will automatically serve static files from the `public/` folder (or you can create a separate `gh-pages` branch).
3. Replace `<YOUR_WORKER_SUBDOMAIN>` in `public/script.js` with the actual subdomain of your Cloudflare worker (e.g., `leakycompute.workers.dev`).

## Defensive Checklist
- **Network isolation** – Bind Ollama to `127.0.0.1` or a private subnet only. If a public endpoint is required, place it behind a reverse‑proxy that enforces TLS and adds an API‑key or mutual‑TLS.
- **Authentication** – Enable Ollama’s built‑in username/password or front‑end it with a reverse‑proxy that requires a bearer token. Never run the service as root; run it in a non‑root Docker container with minimal capabilities.
- **Input validation** – Reject model names containing characters outside `[A‑Z0‑9_.-]`. Whitelist allowed model names.
- **Least‑privilege runtime** – Run the container with a read‑only filesystem, drop unnecessary Linux capabilities, and mount model directories read‑only.
- **Logging & alerting** – Log every request to `/api/ps`, `/api/pull`, `/api/generate`. Alert on abnormal request rates or on payloads containing `..` or `/etc`.
- **Patch & version hygiene** – Keep the Ollama server up‑to‑date. If the vendor does not fix the path‑traversal bug, consider forking or switching to a server with stricter input validation.
- **Monitoring** – Deploy a network IDS rule that flags SSRF payloads targeting `127.0.0.1`, `169.254.*`, `metadata.google.internal`, etc. Correlate Ollama traffic with unusual user‑agents or geolocations.

## License
MIT License (or your preferred license).

---

**Contact**: If you have questions or wish to contribute, open an issue in the repository or reach out via the project's discussion board.