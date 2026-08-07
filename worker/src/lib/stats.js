/** Aggregate public stats — counts only, never raw IPs. */

const STATS_KEY = "stats:live";
const CATALOG_KEY = "catalog:validated";

export async function getLiveStats(env) {
  const defaults = {
    checks_total: 0,
    exposed_total: 0,
    last_check_at: null,
    models_top: [],
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

export async function recordCheckResult(env, { exposed, models }) {
  if (!env.KV) return;
  try {
    const stats = await getLiveStats(env);
    stats.checks_total = (stats.checks_total || 0) + 1;
    if (exposed) stats.exposed_total = (stats.exposed_total || 0) + 1;
    stats.last_check_at = new Date().toISOString();
    stats.updated_at = stats.last_check_at;

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

export function publicStatsPayload(env, live) {
  const snapshot_models = parseInt(env.SNAPSHOT_MODELS || "0", 10) || 0;
  const snapshot_hosts = parseInt(env.SNAPSHOT_HOSTS || "0", 10) || 0;
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
      note: "Counts from voluntary self-checks and researcher-owned scans only.",
    },
    updated_at: live.updated_at || new Date().toISOString(),
  };
}
