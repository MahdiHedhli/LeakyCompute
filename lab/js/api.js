/**
 * The lab's only network layer.
 *
 * I-20 / I-1: every function here builds a URL from `API_BASE` and a hardcoded
 * path constant. There is no parameter, code path, or config key through which
 * a corpus record can become a request destination — a hostile version string
 * or a crafted `ip` cannot steer a fetch anywhere but our own Worker. The lab
 * reads what we already stored; it cannot make the browser touch a discovered
 * host, which is the behaviour the project exists to be distinguishable from.
 *
 * Every request is a GET. There is no write path in the lab API to call.
 */

const PATHS = {
  me: "/v1/research/me",
  catalog: "/v1/research/lab/catalog",
  map: "/v1/research/lab/map",
  validation: "/v1/research/lab/validation",
  host: "/v1/research/lab/host",
};

function cfg() {
  return window.LEAKY_LAB_CONFIG || {};
}

function url(path, params) {
  const base = String(cfg().API_BASE || "").replace(/\/+$/, "");
  const u = new URL(base + path, window.location.href);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
      u.searchParams.set(k, Array.isArray(v) ? v.join(",") : String(v));
    }
  }
  return u.toString();
}

async function get(path, params) {
  const headers = { Accept: "application/json" };
  // Local wrangler dev only; in production Cloudflare Access injects the JWT.
  if (cfg().DEV_GITHUB_LOGIN) headers["X-Dev-GitHub-Login"] = cfg().DEV_GITHUB_LOGIN;
  let res;
  try {
    res = await fetch(url(path, params), { method: "GET", headers, credentials: "include" });
  } catch (err) {
    return { ok: false, status: 0, data: { error: "unreachable", message: String(err?.message || err) } };
  }
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data: data || {} };
}

export function whoami() {
  return get(PATHS.me);
}

export function catalog(params) {
  return get(PATHS.catalog, params);
}

export function map(params) {
  return get(PATHS.map, params);
}

export function validation(params) {
  return get(PATHS.validation, params);
}

/**
 * The one call that takes an address, and it goes to our own Worker with the
 * address as a query parameter it validates as a literal (see lab.js). It is
 * still never used to build a link, an iframe, or a request to the host itself.
 */
export function host(ip, opts = {}) {
  return get(PATHS.host, { ip, include_models: opts.includeModels ? "1" : null });
}
