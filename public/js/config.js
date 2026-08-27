/**
 * Domain-ready public config.
 * Production uses the controlled Worker custom domain. Local pages may still
 * override it through the loopback-only query parameter below.
 * Local pages can override via ?api=https://... for development testing.
 */
window.LEAKY_CONFIG = {
  // Replace after `wrangler deploy`
  API_BASE: "https://api.leakycompute.mahdihedhli.com",
  // Required for the production hosted self-check. Public identifier only.
  TURNSTILE_SITE_KEY: "0x4AAAAAAEeREuGCx3DEpIP7",
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
    const localPage = ["", "localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    if (api && localPage) window.LEAKY_CONFIG.API_BASE = api.replace(/\/+$/, "");
  } catch (_) {}
})();
