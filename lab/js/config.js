window.LEAKY_LAB_CONFIG = {
  API_BASE: "https://leakycompute-api.<your-subdomain>.workers.dev",
  SEED_URL: "data/seed-models.json",
  PUBLIC_URL: "https://mahdihedhli.github.io/LeakyCompute/",
  REPO_URL: "https://github.com/MahdiHedhli/LeakyCompute",
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
