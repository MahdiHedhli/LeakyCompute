window.LEAKY_LAB_CONFIG = {
  // Same-origin by default. The lab now reaches the API through the Pages
  // Function at /v1/research/*, which is what lets Cloudflare Access attach an
  // identity to the request — a cross-origin call to workers.dev cannot carry
  // the Access cookie, so it always arrived unauthenticated.
  // Local dev against wrangler: append ?api=http://127.0.0.1:8787
  API_BASE: "",
  SEED_URL: "data/seed-models.json",
  PUBLIC_URL: "https://mahdihedhli.github.io/LeakyCompute/",
  REPO_URL: "https://github.com/MahdiHedhli/LeakyCompute",
  DONT_PANIC_URL: "https://mahdihedhli.com/dont-panic/",
  ACCESS_ISSUE_URL:
    "https://github.com/MahdiHedhli/LeakyCompute/issues/new?template=request_research_access.yml",
  // Optional: your GitHub login for local dev against wrangler (sends X-Dev-GitHub-Login)
  DEV_GITHUB_LOGIN: "",
};

(function () {
  try {
    const u = new URL(window.location.href);
    const api = u.searchParams.get("api");
    const dev = u.searchParams.get("dev_user");
    if (api) window.LEAKY_LAB_CONFIG.API_BASE = api.replace(/\/+$/, "");
    if (dev) window.LEAKY_LAB_CONFIG.DEV_GITHUB_LOGIN = dev;
  } catch (_) {}
})();
