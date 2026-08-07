/**
 * Domain-ready public config.
 * After deploy, set API_BASE to your workers.dev URL (or custom domain).
 * GitHub Pages can also override via ?api=https://... for local testing.
 */
window.LEAKY_CONFIG = {
  // Replace after `wrangler deploy`
  API_BASE: "https://leakycompute-api.mhedhli.workers.dev",
  // Optional free Turnstile site key; leave empty to skip client widget
  TURNSTILE_SITE_KEY: "",
  LAB_URL: "https://leakycompute-lab.pages.dev",
  REPO_URL: "https://github.com/MahdiHedhli/LeakyCompute",
  DONT_PANIC_URL: "https://mahdihedhli.com/dont-panic/",
  ACCESS_ISSUE_URL:
    "https://github.com/MahdiHedhli/LeakyCompute/issues/new?template=request_research_access.yml",
  // Static fallback snapshot (matches seed) if API unreachable
  SNAPSHOT_FALLBACK: { models: 1864, hosts: 19348 },
};

(function applyQueryOverrides() {
  try {
    const u = new URL(window.location.href);
    const api = u.searchParams.get("api");
    if (api) window.LEAKY_CONFIG.API_BASE = api.replace(/\/+$/, "");
  } catch (_) {}
})();
