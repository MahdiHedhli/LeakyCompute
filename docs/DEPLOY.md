# Deploy guide (free tier)

## 1. Cloudflare Worker API

```bash
npm i -g wrangler   # or use npx
wrangler login

# Create KV
wrangler kv namespace create LEAKY_KV
wrangler kv namespace create LEAKY_KV --preview
```

Paste the ids into `wrangler.toml` (`id` / `preview_id`).

```bash
# Secrets
wrangler secret put ADMIN_SYNC_TOKEN    # long random; also GH secret LEAKY_ADMIN_SYNC_TOKEN
wrangler secret put ABUSE_LOG_SALT      # random salt for IP hashing
# optional:
wrangler secret put TURNSTILE_SECRET_KEY

wrangler deploy
```

Note the `*.workers.dev` URL → set in:

- `public/js/config.js` → `API_BASE`
- `lab/js/config.js` → `API_BASE`
- GitHub secrets: `LEAKY_API_BASE`

Update `ALLOWED_ORIGINS` in `wrangler.toml` / dashboard vars to include:

- `https://<user>.github.io`
- `https://leakycompute-lab.pages.dev` (or your lab Pages URL)
- future custom domains

## 2. GitHub Pages (public pulse)

Repo **Settings → Pages**:

- Source: Deploy from branch `main`
- Folder: `/public`

Site: `https://<user>.github.io/LeakyCompute/`

## 3. Cloudflare Pages (lab UI)

- Create project from this repo
- **Root directory:** `lab`
- Build command: none (static)
- Output: `/` (static)

## 4. Cloudflare Access (GitHub SSO)

1. Zero Trust → **Settings → Authentication → GitHub**
2. **Access → Applications → Add** self-hosted:
   - Application domain: your lab Pages hostname
   - Policy: **Allow** identity provider **GitHub** (authenticated users)
3. Application **AUD** tag → Worker var `ACCESS_AUD`
4. Team domain → Worker var `ACCESS_TEAM_DOMAIN`

Allowlist enforcement is **application-level** (Worker KV) after issue approval — Access only forces GitHub login.

## 5. GitHub secrets for approve/revoke Actions

| Secret | Purpose |
|--------|---------|
| `LEAKY_API_BASE` | Worker URL |
| `LEAKY_ADMIN_SYNC_TOKEN` | Same as Worker `ADMIN_SYNC_TOKEN` |
| `LEAKY_LAB_URL` | Lab URL used in approval comments |

## 6. Labels

Create labels: `access-request`, `needs-review`, `access-approved`, `access-active`, `access-revoked`.

## 7. Approve a researcher

1. Review issue + GitHub profile/repos  
2. Add label **`access-approved`**  
3. Action writes KV allowlist + comments with lab URL  

## 8. Custom domain later

1. Pages / Workers custom domains in CF dashboard  
2. Access app: add hostname  
3. Update `ALLOWED_ORIGINS`, `public/js/config.js`, `lab/js/config.js`, secrets  
4. No code rewrite required beyond config URLs  
