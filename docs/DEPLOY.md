# Deploy guide (free tier)

## Supply-chain baseline

Install tooling from the committed lockfile and run the invariant suite before
deploying:

```bash
npm ci --ignore-scripts
npm test
```

The repository deliberately pins:

- GitHub Actions to full, reviewed commit SHAs (with release comments);
- the CI runner family to `ubuntu-24.04` and Node to an exact patch release;
- Wrangler to the reviewed version in both `package.json`/`package-lock.json`
  and every one-shot `npx` command;
- local fingerprint-lab images to registry manifest digests.

`npm run test:supply-chain` rejects mutable Action refs, `*-latest` runner
labels, ranged npm dependencies, unpinned Wrangler invocations, and local-lab
images without a digest. Dependabot opens update PRs, but an update is not
self-approving: inspect upstream release notes and the resulting diff, preserve
the version comment beside an Action SHA, and rerun the full suite.

The exact references reviewed on 2026-08-25 are recorded in
[`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md).


## Registering a researcher's email privately

Cloudflare Access asserts a GitHub account's **primary email**, not its username,
so an allowlist entry needs both. The access-request template asks for the
address but does not require it in the issue — publishing an email to get access
is a bad trade, so requesters are told they may send it to the maintainer
instead.

When one arrives that way, register it without putting it in the thread:

```bash
# ADMIN_TOKEN is the Worker's ADMIN_SYNC_TOKEN
curl -fsS -X POST "$LEAKY_API_BASE/v1/admin/allowlist" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"op":"approve","login":"THEIR_GITHUB_LOGIN",
       "aliases":["their-primary@example.com"],
       "approved_by":"maintainer"}'
```

Approving again is how you add an alias — the call is idempotent on the login and
replaces the entry, so the researcher does not need a second issue. Revoking the
login clears its aliases too, so there is no second door left open.

Confirm it took by asking the researcher to reload; a refusal now lists the
identities the session presented, so a remaining mismatch is visible rather than
mysterious.


## Live endpoints (bootstrap deploy)

| Resource | URL |
|----------|-----|
| API Worker | `https://api.leakycompute.mahdihedhli.com` |
| Public pulse (GitHub Pages) | `https://leakycompute.mahdihedhli.com/` |
| Researcher lab (CF Pages) | `https://leakycompute-lab.pages.dev` |
| KV prod | `432febf1abd64e9995e33d6081dfd3c7` (`leakycompute-KV`) |

**Still manual:** Cloudflare Access (GitHub SSO) on the lab hostname, Turnstile site keys (optional).

## Deployment ownership — important

The Cloudflare OAuth/Git integration belongs to the **Pages lab only**. It does
not deploy `worker/src/index.js`. The API Worker is deployed locally with
Wrangler's OAuth login. The GitHub `CLOUDFLARE_API_TOKEN` is scoped for the Pages
fallback and cannot deploy Worker scripts.

Do not add a token-based Worker deployment workflow or broaden the Pages token
as a workaround. These paths are separate by design:

| Surface | Owner |
|---|---|
| API Worker | Local Wrangler OAuth + `wrangler deploy` |
| Research lab | Cloudflare Pages Git/OAuth integration |
| Public site | GitHub Pages workflow |

## 1. Cloudflare Worker API

Already deployed as `leakycompute-api`. To redeploy from this repo:

```bash
npx --yes wrangler@4.126.0 login \
  --scopes account:read \
  --scopes user:read \
  --scopes workers_scripts:write \
  --use-keyring
# wrangler.toml already has KV ids
npx --yes wrangler@4.126.0 secret put ADMIN_SYNC_TOKEN
npx --yes wrangler@4.126.0 secret put ABUSE_LOG_SALT  # high-entropy HMAC key; required for abuse logs
# optional:
npx --yes wrangler@4.126.0 secret put TURNSTILE_SECRET_KEY
npx --yes wrangler@4.126.0 deploy
```

The restricted scope list is intentional. Wrangler's default login currently
requests write access across many unrelated Cloudflare products; inspect and
minimise OAuth scopes rather than approving that default.

With this intentionally minimal OAuth grant, Wrangler can upload and promote a
Worker version but then report that it cannot look up the custom-domain zone.
Do not broaden the token to silence that post-upload route check. Confirm the
new version with `npx --yes wrangler@4.126.0 deployments list`, then verify the
custom API hostname directly. Treat the deploy as failed only if the promoted
version or live endpoint is wrong.

The strong-state migration uses `CONTROL_MIGRATION_TOKEN` only as a temporary
bootstrap secret. Set it for migration, verify `/v1/admin/control/health`, full
pagination, purge/retention, and aggregate reconciliation, then delete it:

```bash
npx --yes wrangler@4.126.0 secret delete CONTROL_MIGRATION_TOKEN
```

Do not leave the migration credential installed after activation. The normal
admin token cannot invoke the bootstrap migration route.

`wrangler.toml` also enables Workers Caching and the `STATS_RATE_LIMITER`
binding. These are part of the Worker version and require no additional secret
or dashboard-created resource. Do not remove either independently:
`/v1/stats` relies on caching for normal traffic and the limiter to stop cold
misses or cache-bypass requests before they consume security-state KV reads.

URLs are set in:

- `public/js/config.js` → `API_BASE`
- `lab/js/config.js` → `API_BASE`
- GitHub secrets: `LEAKY_API_BASE`, `LEAKY_ADMIN_SYNC_TOKEN`, `LEAKY_LAB_URL`

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

## 8. Controlled public perimeter

The public topology is deliberately split even though both names are in the
same Cloudflare zone:

| Hostname | Origin/deployment owner | Cloudflare role |
|---|---|---|
| `api.leakycompute.mahdihedhli.com` | Worker, deployed locally through scoped Wrangler OAuth | Worker Custom Domain + WAF |
| `leakycompute.mahdihedhli.com` | GitHub Pages workflow | Proxied DNS + response-header rules |

The Pages hostname must be registered in GitHub before its proxied CNAME is
created. Verify GitHub's domain ownership/HTTPS state and the redirect from the
legacy `github.io` URL before treating the header boundary as complete.

The API migration keeps `workers.dev` temporarily while callers move. Disable
it only by committing `workers_dev = false` and `preview_urls = false` after the public site, discovery
scripts, Pages research bridge, repository secrets, and live verification all
use the custom domain. Dashboard-only disabling is not durable because a later
Wrangler deployment can re-enable it from configuration.

See [PERIMETER.md](PERIMETER.md) for the reviewed WAF and response-header policy.
