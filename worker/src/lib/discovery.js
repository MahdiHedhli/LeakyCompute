/**
 * Private discovery hit store + catalog merge.
 * Raw IPs never leave via public endpoints — admin token only.
 */

const HITS_INDEX = "discovery:hits_index";
const HIT_PREFIX = "discovery:hit:";
const MAX_INDEX = 5000;

export async function recordExposedHost(env, { ip, port, models, source }) {
  if (!env.KV || !ip) return;
  const key = `${HIT_PREFIX}${ip}`;
  const now = new Date().toISOString();
  const prev = (await env.KV.get(key, "json")) || {};
  const entry = {
    ip,
    port: port || 11434,
    first_seen: prev.first_seen || now,
    last_seen: now,
    times_seen: (prev.times_seen || 0) + 1,
    models: models || prev.models || [],
    source: source || prev.source || "check",
  };
  await env.KV.put(key, JSON.stringify(entry));

  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];
  if (!index.includes(ip)) {
    index.push(ip);
    if (index.length > MAX_INDEX) {
      // drop oldest entries from index (keep recent tail)
      index = index.slice(-MAX_INDEX);
    }
    await env.KV.put(HITS_INDEX, JSON.stringify(index));
  }
}

export async function listHits(env, { limit = 500 } = {}) {
  if (!env.KV) return [];
  const index = (await env.KV.get(HITS_INDEX, "json")) || [];
  const ips = (Array.isArray(index) ? index : []).slice(-Math.min(limit, MAX_INDEX));
  const out = [];
  // sequential get to stay under free subrequest patterns
  for (const ip of ips) {
    const row = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
    if (row) out.push(row);
  }
  return out;
}

export async function mergeValidatedModels(env, modelHits) {
  // modelHits: [{ model, hosts_delta, source }]
  if (!env.KV || !Array.isArray(modelHits)) return;
  const catalog = (await env.KV.get("catalog:validated", "json")) || {
    models: [],
    updated_at: null,
  };
  const byName = Object.create(null);
  for (const m of catalog.models || []) {
    byName[m.model] = m;
  }
  for (const hit of modelHits) {
    const name = hit.model;
    if (!name) continue;
    const prev = byName[name] || {
      model: name,
      hosts: 0,
      size: hit.size || "?",
      validated: true,
      source: hit.source || "discovery",
    };
    prev.hosts = Math.max(prev.hosts || 0, hit.hosts || 1);
    prev.validated = true;
    prev.last_validated = new Date().toISOString();
    prev.source = hit.source || prev.source;
    byName[name] = prev;
  }
  catalog.models = Object.values(byName)
    .sort((a, b) => (b.hosts || 0) - (a.hosts || 0))
    .slice(0, 2500);
  catalog.updated_at = new Date().toISOString();
  await env.KV.put("catalog:validated", JSON.stringify(catalog));
  return catalog;
}

export async function ingestDiscoveryBatch(env, batch) {
  /**
   * batch: {
   *   results: [{ ip, port, exposed, models: [{name,size}], source }],
   *   run_meta?: object
   * }
   */
  const results = batch.results || [];
  let exposed = 0;
  const modelHits = [];
  for (const r of results) {
    if (!r || !r.ip) continue;
    if (r.exposed) {
      exposed++;
      const models = (r.models || []).map((m) => ({
        name: m.name || m.model,
        size: m.size || null,
      }));
      await recordExposedHost(env, {
        ip: r.ip,
        port: r.port || 11434,
        models,
        source: r.source || "discovery",
      });
      for (const m of models) {
        if (m.name) {
          modelHits.push({
            model: m.name,
            hosts: 1,
            size: m.size,
            source: r.source || "discovery",
          });
        }
      }
    }
  }
  if (modelHits.length) await mergeValidatedModels(env, modelHits);

  // bump live stats
  const statsKey = "stats:live";
  const stats = (await env.KV.get(statsKey, "json")) || {
    checks_total: 0,
    exposed_total: 0,
    models_top: [],
  };
  stats.checks_total = (stats.checks_total || 0) + results.length;
  stats.exposed_total = (stats.exposed_total || 0) + exposed;
  stats.last_check_at = new Date().toISOString();
  stats.updated_at = stats.last_check_at;
  stats.discovery_runs = (stats.discovery_runs || 0) + 1;
  stats.last_discovery_at = stats.last_check_at;
  if (batch.run_meta) stats.last_discovery_meta = batch.run_meta;
  await env.KV.put(statsKey, JSON.stringify(stats));

  return {
    ingested: results.length,
    exposed,
    models_touched: modelHits.length,
  };
}
