/** Aggregate public stats — counts only, never raw IPs. */

const STATS_KEY = "stats:live";
const CATALOG_KEY = "catalog:validated";

export async function getLiveStats(env) {
  const defaults = {
    checks_total: 0,
    exposed_total: 0,
    last_check_at: null,
    models_top: [],
    by_service: {},
    updated_at: null,
  };
  if (!env.KV) return defaults;
  try {
    const raw = await env.KV.get(STATS_KEY, "json");
    return { ...defaults, ...(raw || {}) };
  } catch {
    return defaults;
  }
}

export async function recordCheckResult(env, { exposed, models, services }) {
  if (!env.KV) return;
  try {
    const stats = await getLiveStats(env);
    stats.checks_total = (stats.checks_total || 0) + 1;
    if (exposed) stats.exposed_total = (stats.exposed_total || 0) + 1;
    stats.last_check_at = new Date().toISOString();
    stats.updated_at = stats.last_check_at;

    // Per-service tallies: one check now covers several services, so
    // exposed_total alone no longer says which stack was open.
    if (Array.isArray(services) && services.length) {
      const by = { ...(stats.by_service || {}) };
      for (const s of services) {
        const row = by[s.service] || { checks: 0, detected: 0, exposed: 0 };
        row.checks += 1;
        if (s.detected) row.detected += 1;
        if (s.exposed) row.exposed += 1;
        by[s.service] = row;
      }
      stats.by_service = by;
    }

    // top models (rough counts from exposed responses)
    if (exposed && Array.isArray(models)) {
      const top = Object.create(null);
      for (const row of stats.models_top || []) {
        top[row.model] = row.count;
      }
      for (const m of models) {
        const name = m.name || m.model;
        if (!name) continue;
        top[name] = (top[name] || 0) + 1;
      }
      stats.models_top = Object.entries(top)
        .map(([model, count]) => ({ model, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 25);
    }

    await env.KV.put(STATS_KEY, JSON.stringify(stats));
  } catch {
    // ignore
  }
}


export async function getValidatedCatalog(env) {
  if (!env.KV) return { models: [], updated_at: null };
  try {
    const raw = await env.KV.get(CATALOG_KEY, "json");
    return raw || { models: [], updated_at: null };
  } catch {
    return { models: [], updated_at: null };
  }
}

export async function putValidatedCatalog(env, catalog) {
  if (!env.KV) return;
  await env.KV.put(
    CATALOG_KEY,
    JSON.stringify({
      models: catalog.models || [],
      updated_at: new Date().toISOString(),
    })
  );
}

export async function publicStatsPayload(env, live) {
  const snapshot_models = parseInt(env.SNAPSHOT_MODELS || "0", 10) || 0;
  const snapshot_hosts = parseInt(env.SNAPSHOT_HOSTS || "0", 10) || 0;
  // lazy import to avoid circular issues at module init
  const { getGeoStats } = await import("./discovery.js");
  const geo = await getGeoStats(env);
  return {
    research_snapshot: {
      label: "Research snapshot (archive seed)",
      models: snapshot_models,
      hosts: snapshot_hosts,
      note: "Derived from Wayback-era STOLEN COMPUTE catalog after exploit-payload filtering. Not a live internet census.",
    },
    live_instrumented: {
      label: "Live instrumented",
      checks_total: live.checks_total || 0,
      exposed_total: live.exposed_total || 0,
      last_check_at: live.last_check_at,
      models_top: live.models_top || [],
      by_service: live.by_service || {},
      note:
        "Counts from voluntary self-checks and capped multi-lane discovery (Shodan fingerprints + prior-hit neighborhoods). Not a full internet census.",
      discovery_runs: live.discovery_runs || 0,
      last_discovery_at: live.last_discovery_at || null,
    },
    geography: {
      label: "Exposure candidates by country",
      note: "Unique exposed hosts we have re-verified (country from Shodan/geo metadata). No raw IPs.",
      by_country: geo.by_country || [],
      by_asn: (geo.by_asn || []).slice(0, 20),
      by_stack: geo.by_stack || [],
    },
    updated_at: live.updated_at || new Date().toISOString(),
  };
}
