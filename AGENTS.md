# LeakyCompute agent instructions

## Deployment topology — do not infer or unify these paths

This repository deliberately uses three different deployment mechanisms:

| Surface | Deployment path |
|---|---|
| API Worker (`leakycompute-api`) | Run Wrangler locally and authenticate through Wrangler's Cloudflare OAuth flow. It is **not** deployed by a GitHub Actions API token or by the repository's Cloudflare Pages integration. |
| Research lab (`leakycompute-lab.pages.dev`) | Cloudflare Pages Git integration, authenticated through the Cloudflare GitHub OAuth app. A push touching `lab/**` or `functions/**` deploys it. |
| Public site | GitHub Pages through `.github/workflows/deploy-pages.yml`. |

The repository secret `CLOUDFLARE_API_TOKEN` exists for the Pages fallback and
monitoring workflow. It does not have Worker-script permission. Do not create a
GitHub Actions Worker-deployment workflow, reuse that token for the Worker, or
broaden its permissions unless the maintainer explicitly changes the deployment
architecture.

For a Worker deployment, use an exact reviewed Wrangler version and request only
the OAuth scopes required here:

```bash
npx --yes wrangler@4.126.0 login \
  --scopes account:read \
  --scopes user:read \
  --scopes workers_scripts:write \
  --use-keyring
npx --yes wrangler@4.126.0 deploy
```

Do not accept Wrangler's default all-product OAuth scope list. If the reviewed
Wrangler version changes, update both commands together and inspect the requested
scopes before approving them.

After deployment, verify the hosted-check kill switch without sending a target
probe. POST a body with `target=127.0.0.1` and `authorized=false`; the patched
Worker returns `503 hosted_checks_temporarily_disabled` before parsing the body.
The prior deployment returns `400 authorization_required`, so this safely
distinguishes the versions without emitting target traffic.

See `docs/DEPLOY.md` and `docs/SECURITY_REVIEW_2026-08-25.md` before changing
deployment or re-enabling hosted/active checks.
