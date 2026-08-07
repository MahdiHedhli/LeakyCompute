/**
 * Tier-2: OSV.dev version → vulnerability lookup.
 * Cached in KV (24h) to stay free-tier friendly.
 * Never sends exploit traffic — only external OSV API + version strings we already have.
 */

const OSV_URL = "https://api.osv.dev/v1/query";
const CACHE_TTL_SEC = 60 * 60 * 24; // 24h
const MAX_VULNS_PER_SERVICE = 12;

/** Map checker service id → OSV package identity */
export const OSV_PACKAGES = {
  ollama: { ecosystem: "Go", name: "github.com/ollama/ollama" },
  ray: { ecosystem: "PyPI", name: "ray" },
  jupyter: { ecosystem: "PyPI", name: "jupyter_server" },
  // tier-2 candidates (ready when services.js grows)
  vllm: { ecosystem: "PyPI", name: "vllm" },
  mlflow: { ecosystem: "PyPI", name: "mlflow" },
};

function cacheKey(ecosystem, name, version) {
  return `osv:cache:${ecosystem}:${name}:${version}`;
}

function severityFromOsv(v) {
  // Prefer database_specific / severity array
  const sevArr = v.severity || [];
  for (const s of sevArr) {
    const score = s.score || "";
    // CVSS_V3 like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    const m = /\/([CH])[:/]/.exec(score) || null;
    if (score.includes("AV:N") && (score.includes("C:H") || score.includes("I:H"))) {
      return "critical";
    }
  }
  const db = v.database_specific || {};
  const s = String(db.severity || db.Severity || "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(s)) return s;
  // GHSA often has no severity — default medium for listed CVEs
  if (String(v.id || "").startsWith("CVE-") || String(v.id || "").startsWith("GHSA-")) {
    return "high";
  }
  return "medium";
}

function normalizeOsvVuln(v) {
  const aliases = v.aliases || [];
  const cve = aliases.find((a) => String(a).startsWith("CVE-")) || null;
  return {
    id: v.id,
    cve,
    aliases: aliases.slice(0, 6),
    title: (v.summary || v.details || v.id || "OSV vulnerability").slice(0, 200),
    severity: severityFromOsv(v),
    source: "osv.dev",
    published: v.published || null,
    modified: v.modified || null,
    references: (v.references || [])
      .slice(0, 4)
      .map((r) => r.url)
      .filter(Boolean),
  };
}

/**
 * Query OSV for one package version. Returns [] on failure / no package.
 */
export async function queryOsv(packageInfo, version, env) {
  if (!packageInfo?.name || !packageInfo?.ecosystem || !version) return [];
  const ver = String(version).replace(/^v/i, "").trim();
  if (!ver || ver.length > 64) return [];

  const key = cacheKey(packageInfo.ecosystem, packageInfo.name, ver);
  if (env?.KV) {
    try {
      const cached = await env.KV.get(key, "json");
      if (cached && Array.isArray(cached.vulns)) return cached.vulns;
    } catch {
      // ignore cache read errors
    }
  }

  let vulns = [];
  try {
    const resp = await fetch(OSV_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        version: ver,
        package: {
          name: packageInfo.name,
          ecosystem: packageInfo.ecosystem,
        },
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      const list = data.vulns || [];
      vulns = list.slice(0, MAX_VULNS_PER_SERVICE).map(normalizeOsvVuln);
    }
  } catch {
    vulns = [];
  }

  if (env?.KV) {
    try {
      await env.KV.put(key, JSON.stringify({ vulns, cached_at: new Date().toISOString() }), {
        expirationTtl: CACHE_TTL_SEC,
      });
    } catch {
      // ignore cache write
    }
  }
  return vulns;
}

/**
 * Enrich structured service results with OSV vulns when version is known.
 * Mutates services in place; returns same array.
 */
export async function enrichServicesWithOsv(services, env) {
  if (!Array.isArray(services)) return services;
  await Promise.all(
    services.map(async (svc) => {
      if (!svc?.detected || !svc.version) {
        svc.osv = [];
        return;
      }
      const pkg = OSV_PACKAGES[svc.service];
      if (!pkg) {
        svc.osv = [];
        return;
      }
      const vulns = await queryOsv(pkg, svc.version, env);
      svc.osv = vulns;
      // Attach top OSV hits as findings (don't drown the exposure finding)
      if (vulns.length && svc.exposed) {
        const findings = Array.isArray(svc.findings) ? svc.findings.slice() : [];
        for (const v of vulns.slice(0, 5)) {
          findings.push({
            id: v.cve || v.id,
            title: v.title,
            severity: v.severity,
            detail: `OSV reports this version (${svc.version}) is affected (${v.id}).`,
            endpoint: null,
            source: "osv.dev",
          });
        }
        svc.findings = findings;
      }
    })
  );
  return services;
}
