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

export async function publicStatsPayload(env, live, { authoritative = null } = {}) {
  const snapshot_models = parseInt(env.SNAPSHOT_MODELS || "0", 10) || 0;
  const snapshot_hosts = parseInt(env.SNAPSHOT_HOSTS || "0", 10) || 0;
  // lazy import to avoid circular issues at module init
  const { getGeoStats, getCorpusCounts, getCountryStackStats, getVulnSummary, RETENTION_DAYS } =
    await import("./discovery.js");
  const { exposureClassCounts } = await import("./exposure.js");
  const legacyGeo = await getGeoStats(env);
  const legacyCountryStack = await getCountryStackStats(env);
  const vulnSummary = await getVulnSummary(env);
  const corpus = await getCorpusCounts(env);
  const dimensions = authoritative?.dimensions || null;
  const toSorted = (map, keyName, max = 50) => Object.entries(map || {})
    .map(([key, count]) => ({ [keyName]: key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, max);
  const geo = dimensions ? {
    by_country: toSorted(dimensions.country, "country"),
    by_asn: toSorted(dimensions.asn, "asn"),
    by_stack: toSorted(dimensions.stack, "stack"),
  } : legacyGeo;
  const countryStack = dimensions?.country_stack || legacyCountryStack;
  const reverifiedHosts = dimensions?.corpus?.reverified_hosts ?? corpus.reverified_hosts ?? 0;
  return {
    // Spec §4: three provenance-separated numbers, never summed. They answer
    // different questions — what an archive once listed, what an index lists
    // now, and what answered us — and adding them would manufacture a total
    // nobody measured. research_snapshot/live_instrumented below are the older
    // shape and stay until the page moves over.
    counts_note:
      "archive_snapshot, indexed_observed and reverified are three separate measurements with different provenance. They are never summed.",
    archive_snapshot: {
      label: "Archive snapshot",
      hosts: snapshot_hosts,
      models: snapshot_models,
      as_of: env.SNAPSHOT_AS_OF || null,
      source: "filtered STOLEN COMPUTE catalog",
      note: "Listed as exposed in an archive-era catalog. Not re-verified, so it says nothing about today.",
    },
    indexed_observed: {
      label: "Indexed now",
      hosts: corpus.indexed_observed_hosts || 0,
      // Censys is declared at zero rather than omitted: a source we intend to
      // add should be visibly absent, so the shape of what is missing is on the
      // page instead of only in the roadmap.
      sources: {
        shodan: 0,
        censys: 0,
        other: 0,
        user_submitted: 0,
        ...(corpus.indexed_observed_sources || {}),
      },
      source: corpus.indexed_observed_source || "public index records, counted not probed",
      last_observed_at: corpus.last_observed_at || null,
      note:
        "Counted from public index records and user-submitted requests. " +
        "We sent these hosts nothing to arrive at this number (I-21).",
    },
    reverified: {
      label: "Re-verified",
      hosts: reverifiedHosts,
      window_days: RETENTION_DAYS,
      source: "read-only GET by us",
      last_reverified_at: authoritative?.completed_at || corpus.last_reverified_at || null,
      // Q-3 and Q-4 both bound this number; the card must carry them or the
      // reader takes it for the population.
      note:
        "Hosts that answered a read-only GET from us within the retention window. " +
        "Bounded by what public indexes list (source bias unsettled), and tunnelled exposure is invisible to it.",
    },
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
      // Counts follow record retention now: a host that stops answering ages
      // out of the corpus and out of these totals (I-26). Still counts only,
      // never addresses (I-14).
      note: "Unique exposed hosts currently retained, i.e. re-verified in the last 180 days (country from Shodan/geo metadata). No raw IPs.",
      by_country: geo.by_country || [],
      by_asn: (geo.by_asn || []).slice(0, 20),
      by_stack: geo.by_stack || [],
      // Country x stack, so the UI can answer "what is exposed here" on hover
      // without another request. Aggregate counts only — no addresses (I-14).
      by_country_stack: Object.entries(countryStack).reduce((acc, [pair, n]) => {
        const [cc, stack] = String(pair).split("|");
        if (!cc || !stack || !(n > 0)) return acc;
        (acc[cc] ||= {})[stack] = n;
        return acc;
      }, {}),
    },
    // What each open endpoint enables. Derived from by_stack, so it covers the
    // whole corpus rather than the minority that discloses a version.
    exposure: exposureClassCounts(geo.by_stack || []),
    // Secondary, and labelled with its own denominator: only ~1 host in 8
    // publishes a version, so this cannot describe the corpus.
    known_cves: vulnSummary,
    updated_at: live.updated_at || new Date().toISOString(),
  };
}
