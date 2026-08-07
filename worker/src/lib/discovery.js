/**
 * Private discovery hit store + catalog merge + country aggregates.
 * Raw IPs never leave via public endpoints — admin token only.
 * Country/ASN counts are safe for public stats.
 */

const HITS_INDEX = "discovery:hits_index";
const HIT_PREFIX = "discovery:hit:";
const GEO_KEY = "stats:by_country";
const ASN_KEY = "stats:by_asn";
const STACK_KEY = "stats:by_stack";
const MAX_INDEX = 5000;

export async function recordExposedHost(env, hit) {
  if (!env.KV || !hit?.ip) return;
  const ip = hit.ip;
  const key = `${HIT_PREFIX}${ip}`;
  const now = new Date().toISOString();
  const prev = (await env.KV.get(key, "json")) || {};
  const entry = {
    ip,
    port: hit.port || prev.port || 11434,
    first_seen: prev.first_seen || now,
    last_seen: now,
    times_seen: (prev.times_seen || 0) + 1,
    models: hit.models || prev.models || [],
    source: hit.source || prev.source || "check",
    stack: hit.stack || prev.stack || null,
    product: hit.product || prev.product || null,
    country: hit.country || prev.country || null,
    country_code: hit.country_code || prev.country_code || null,
    city: hit.city || prev.city || null,
    asn: hit.asn || prev.asn || null,
    org: hit.org || prev.org || null,
    vulns: hit.vulns || prev.vulns || [],
  };
  await env.KV.put(key, JSON.stringify(entry));

  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];
  if (!index.includes(ip)) {
    index.push(ip);
    if (index.length > MAX_INDEX) index = index.slice(-MAX_INDEX);
    await env.KV.put(HITS_INDEX, JSON.stringify(index));
  }

  // Only count unique first-seen toward geo/asn/stack public aggregates
  if (!prev.first_seen) {
    await bumpCounter(env, GEO_KEY, entry.country_code || entry.country || "ZZ");
    if (entry.asn) await bumpCounter(env, ASN_KEY, entry.asn);
    if (entry.stack) await bumpCounter(env, STACK_KEY, entry.stack);
  }
}

async function bumpCounter(env, mapKey, label) {
  if (!label) return;
  const map = (await env.KV.get(mapKey, "json")) || {};
  map[label] = (map[label] || 0) + 1;
  await env.KV.put(mapKey, JSON.stringify(map));
}

export async function getGeoStats(env) {
  if (!env.KV) {
    return { by_country: [], by_asn: [], by_stack: [] };
  }
  const countries = (await env.KV.get(GEO_KEY, "json")) || {};
  const asns = (await env.KV.get(ASN_KEY, "json")) || {};
  const stacks = (await env.KV.get(STACK_KEY, "json")) || {};
  const toSorted = (obj, keyName) =>
    Object.entries(obj)
      .map(([k, count]) => ({ [keyName]: k, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 50);
  return {
    by_country: toSorted(countries, "country"),
    by_asn: toSorted(asns, "asn"),
    by_stack: toSorted(stacks, "stack"),
  };
}

export async function listHits(env, { limit = 500, sort = "last_seen" } = {}) {
  if (!env.KV) return [];
  const index = (await env.KV.get(HITS_INDEX, "json")) || [];
  const ips = (Array.isArray(index) ? index : []).slice(-Math.min(limit, MAX_INDEX));
  const out = [];
  for (const ip of ips) {
    const row = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
    if (row) out.push(row);
  }
  if (sort === "country") {
    out.sort((a, b) =>
      String(a.country_code || a.country || "ZZ").localeCompare(
        String(b.country_code || b.country || "ZZ")
      )
    );
  } else if (sort === "asn") {
    out.sort((a, b) => String(a.asn || "").localeCompare(String(b.asn || "")));
  } else {
    out.sort((a, b) => String(b.last_seen || "").localeCompare(String(a.last_seen || "")));
  }
  return out;
}

export async function mergeValidatedModels(env, modelHits) {
  if (!env.KV || !Array.isArray(modelHits)) return;
  const catalog = (await env.KV.get("catalog:validated", "json")) || {
    models: [],
    updated_at: null,
  };
  const byName = Object.create(null);
  for (const m of catalog.models || []) byName[m.model] = m;
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
   * results: [{ ip, port, exposed, models, source, stack, country, country_code, city, asn, org, product, vulns }]
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
        stack: r.stack || null,
        product: r.product || null,
        country: r.country || null,
        country_code: r.country_code || null,
        city: r.city || null,
        asn: r.asn || null,
        org: r.org || null,
        vulns: r.vulns || [],
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
