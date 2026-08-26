# Public perimeter configuration

**Status:** active as of 2026-08-26. The custom public and API hostnames, edge
headers, rate limit, lab bridge, and legacy-route retirement were verified.

This is the reviewed, reproducible record for Cloudflare zone controls that do
not live in Worker source. It does not change deployment ownership: the API
Worker deploys locally through scoped Wrangler OAuth, the public site deploys
through GitHub Pages, and the research lab deploys through Cloudflare Pages Git
OAuth.

## Hostnames

| Hostname | Role | Origin |
|---|---|---|
| `api.leakycompute.mahdihedhli.com` | Public and gated API | `leakycompute-api` Worker Custom Domain |
| `leakycompute.mahdihedhli.com` | Public status and opt-out site | GitHub Pages, proxied by Cloudflare |
| `leakycompute-lab.pages.dev` | Access-gated researcher lab | Cloudflare Pages Git integration |

No wildcard DNS record is permitted for this project.

## API WAF rate rule

The active zone rule is named `LeakyCompute API perimeter` and is scoped to the
API hostname:

- expression: `http.host eq "api.leakycompute.mahdihedhli.com" and starts_with(http.request.uri.path, "/v1/")`
- counting characteristic: source IP (Free-plan behavior)
- threshold: 60 requests per 10 seconds
- mitigation: block for 10 seconds with the default `429`
- cached assets: do not count

This is a coarse perimeter backstop, not authorization or exact accounting.
The Worker's route-specific controls still enforce the stricter security
boundaries, including the two-per-minute, per-location cold-build limit for
`/v1/stats`.

## Public-site response headers

The active Transform Rule is named `LeakyCompute public security headers` and
applies only when:

```text
http.host eq "leakycompute.mahdihedhli.com"
```

Set, replacing any origin value:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.leakycompute.mahdihedhli.com; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

Do not enable HSTS preload or `includeSubDomains` as part of this cutover.
Consider hostname-scoped HSTS only after the custom hostname, certificate,
redirect, and rollback paths have been stable.

## Cutover verification

1. `GET https://api.leakycompute.mahdihedhli.com/v1/health` returns `200`.
2. Two canonical stats requests produce an edge `MISS` followed by `HIT`.
3. A query-bearing stats URL returns uncached `400 canonical_stats_url_required`.
4. The safe kill-switch discriminator returns `503
   hosted_checks_temporarily_disabled` without sending target traffic.
5. The public site loads from `https://leakycompute.mahdihedhli.com/`, calls only
   the custom API hostname, and receives every header above.
6. The legacy GitHub Pages URL redirects to the protected custom hostname.
7. The Access-gated lab bridge reaches every allowlisted research route through
   the custom API hostname.
8. Set `workers_dev = false` and `preview_urls = false`, deploy with the exact
   reviewed Wrangler version, and verify the old URL no longer serves the API.
