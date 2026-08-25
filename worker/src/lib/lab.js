/**
 * Researcher lab backend — query, map and validate the corpus we already hold.
 *
 * Everything in this module reads stored records. It emits no traffic to a
 * discovered host, in any code path, for any query string. There is no target
 * parameter, no URL parameter, no "try this endpoint", and no live probe
 * trigger — the single behaviour I-20 exists to keep this project
 * distinguishable from STOLEN COMPUTE is the one thing the lab cannot do.
 * The only outbound call here is OSV.dev version lookup (see osv.js), which
 * asks a vulnerability database about a version string; it is not a request to
 * a third-party target and is not covered by I-1/I-2's GET rule.
 *
 * Gating: every handler resolves Cloudflare Access identity *and* the
 * researcher allowlist itself rather than trusting the router. Raw addresses
 * leave the Worker only through these handlers (I-14), so mis-wiring a route
 * must not be able to publish them.
 *
 * Retention and disclosure posture is carried on every record rather than
 * assumed by the caller: freshness against the I-24 re-probe interval, expiry
 * against the I-26 180-day silence horizon, and an I-27 `publishable` flag so a
 * researcher can see the corpus without a downstream surface mistaking lab
 * access for permission to publish a host.
 */

import { json } from "./cors.js";
import { consume, intEnv } from "./ratelimit.js";
import { logAbuse } from "./abuse.js";
import { resolveResearcher } from "./access.js";
import { matchAllowEntry } from "./allowlist.js";
import { listHits } from "./discovery.js";
import { getLiveStats } from "./stats.js";
import { loadExclusions, isExcluded, parseExclusionEntry } from "./exclusions.js";
import { SERVICES } from "./services.js";
import { matchAdvisories } from "./vuln.js";
import { OSV_PACKAGES, queryOsv } from "./osv.js";

const ROUTE_PREFIX = "/v1/research/lab";

/**
 * KV read budget, not squeamishness: assembling the corpus costs one KV get per
 * host, and those count against the Worker's subrequest ceiling. Every response
 * says whether it hit the cap so no researcher mistakes a truncated scan for
 * the whole corpus.
 */
const DEFAULT_SCAN = 250;
const MAX_SCAN = 400;

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

/** I-24: at most one probe cycle per host per 14 days. */
const REPROBE_INTERVAL_DAYS = 14;
/** I-26: a record is deleted 180 days after its last *successful* probe. */
const EXPIRY_DAYS = 180;
/** I-27: 90 days from first notification attempt to host-identifying publication. */
const DISCLOSURE_WINDOW_DAYS = 90;

/** OSV is an external API call per distinct (stack, version) pair — bound it. */
const OSV_LOOKUP_CAP = 20;

const DAY_MS = 86400000;

/**
 * Fields whose contents were produced by a probed host. I-16: they are
 * attacker-controlled, so they ship with a machine-readable warning and the
 * client is expected to escape them at render time.
 */
const UNTRUSTED_FIELDS = [
  "version",
  "product",
  "org",
  "city",
  "country",
  "models",
  "vulns[].id",
  "vulns[].title",
];

const LIMITATIONS = [
  "The corpus is bounded by what public indexes list (I-22), so it inherits their bias — Q-3 is unsettled and these counts are not a population sample.",
  "Tunnelled exposure (ngrok, trycloudflare, Tailscale Funnel) is structurally invisible (Q-4). Absence from the corpus is not evidence of absence.",
  "A host that stopped answering may have been remediated, re-addressed, or moved behind CGNAT. Silence is not a fix.",
  "Stack counts are host x stack pairs: one host exposing two stacks counts in both buckets, so per-stack totals sum to more than the host count.",
];

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

class LabError extends Error {
  constructor(status, code, message, extra) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.extra = extra || null;
  }
}

function badRequest(code, message, extra) {
  return new LabError(400, code, message, extra);
}

/* ------------------------------------------------------------------ */
/* Untrusted-string handling (I-16)                                    */
/* ------------------------------------------------------------------ */

/**
 * Strip control characters and bidirectional overrides, collapse whitespace,
 * and cap length. This is defence in depth, not a substitute for escaping at
 * render time: a hostile version banner should not be able to smuggle a line
 * break into a log line, reorder a table row, or blow up a lab page with a
 * 32 KB "product" string.
 */
function clean(value, max = 160) {
  if (value == null) return null;
  const s = String(value)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!s) return null;
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

const IPV4_LITERAL =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const IPV6_LITERAL = /^[0-9a-fA-F:]{2,45}$/;

/**
 * The host-detail route reads one KV key built from a caller-supplied address.
 * Only a literal v4/v6 address is accepted so the parameter can never be used
 * to reach a key outside the hit namespace.
 */
function isIpLiteral(s) {
  const v = String(s || "").trim();
  if (IPV4_LITERAL.test(v)) return true;
  return v.includes(":") && IPV6_LITERAL.test(v);
}

function toMs(value) {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? t : null;
}

function daysSince(ms, now) {
  if (ms == null) return null;
  return Math.max(0, Math.round(((now - ms) / DAY_MS) * 10) / 10);
}

function isoPlusDays(ms, days) {
  if (ms == null) return null;
  return new Date(ms + days * DAY_MS).toISOString();
}

function normAsn(value) {
  if (value == null || value === "") return null;
  const m = /^(?:as)?(\d{1,10})$/i.exec(String(value).trim());
  return m ? `AS${Number(m[1])}` : clean(value, 24);
}

function parseList(params, name) {
  const out = [];
  for (const raw of params.getAll(name)) {
    for (const part of String(raw).split(",")) {
      const v = part.trim();
      if (v) out.push(v);
    }
  }
  return out;
}

function parseIntParam(params, name, fallback, { min = 1, max } = {}) {
  const raw = params.get(name);
  if (raw == null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n)) throw badRequest("invalid_parameter", `${name} must be an integer`);
  if (n < min) throw badRequest("invalid_parameter", `${name} must be >= ${min}`);
  return max != null ? Math.min(n, max) : n;
}

function parseDateParam(params, name) {
  const raw = params.get(name);
  if (!raw) return null;
  const t = Date.parse(raw);
  if (!Number.isFinite(t)) {
    throw badRequest("invalid_parameter", `${name} must be an ISO-8601 date`);
  }
  return t;
}

function countBy(rows, keyFn, { limit = 50, extra } = {}) {
  const map = new Map();
  for (const row of rows) {
    for (const key of [].concat(keyFn(row) ?? [])) {
      if (key == null || key === "") continue;
      const cur = map.get(key) || { key, count: 0, rows: [] };
      cur.count += 1;
      if (extra) cur.rows.push(row);
      map.set(key, cur);
    }
  }
  const sorted = [...map.values()].sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)));
  const out = sorted.slice(0, limit).map((entry) => {
    const base = { key: entry.key, hosts: entry.count };
    if (extra) Object.assign(base, extra(entry.rows));
    return base;
  });
  return { top: out, distinct: map.size, truncated: map.size > out.length };
}

/**
 * Cross-tab as a sparse cell list. Rows and columns are capped independently so
 * a corpus with thousands of ASNs cannot produce an unbounded payload.
 */
function crossTab(rows, rowKeyFn, colKeyFn, { maxRows = 15, maxCols = 15 } = {}) {
  const rowTotals = new Map();
  const colTotals = new Map();
  const cells = new Map();
  for (const row of rows) {
    // Deduped per row and counted once per key before the cell loop. Counting
    // inside it would add a host to its country total once per stack it
    // exposes, so the Σ row would disagree with the by_country card built by
    // countBy() on the same screen — for the same corpus, in the same response.
    const rKeys = new Set([].concat(rowKeyFn(row) ?? []).filter((k) => k != null && k !== ""));
    const cKeys = new Set([].concat(colKeyFn(row) ?? []).filter((k) => k != null && k !== ""));
    for (const r of rKeys) rowTotals.set(r, (rowTotals.get(r) || 0) + 1);
    for (const c of cKeys) colTotals.set(c, (colTotals.get(c) || 0) + 1);
    for (const r of rKeys) {
      for (const c of cKeys) {
        const k = JSON.stringify([r, c]);
        cells.set(k, (cells.get(k) || 0) + 1);
      }
    }
  }
  const pick = (m, n) =>
    [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))).slice(0, n);
  const topRows = pick(rowTotals, maxRows);
  const topCols = pick(colTotals, maxCols);
  const rowSet = new Set(topRows.map(([k]) => k));
  const colSet = new Set(topCols.map(([k]) => k));
  const outCells = [];
  for (const [k, count] of cells) {
    const [r, c] = JSON.parse(k);
    if (rowSet.has(r) && colSet.has(c)) outCells.push({ row: r, col: c, hosts: count });
  }
  outCells.sort((a, b) => b.hosts - a.hosts);
  return {
    rows: topRows.map(([key, hosts]) => ({ key, hosts })),
    cols: topCols.map(([key, hosts]) => ({ key, hosts })),
    cells: outCells,
    truncated: rowTotals.size > topRows.length || colTotals.size > topCols.length,
  };
}

/* ------------------------------------------------------------------ */
/* Gating                                                              */
/* ------------------------------------------------------------------ */

/**
 * Access identity + allowlist, checked here rather than in the router.
 * Denials are logged for the same reason override refusals are: a pattern of
 * unauthenticated lab probing is worth seeing.
 */
async function gate(request, env, action) {
  const identity = await resolveResearcher(request, env);
  if (!identity) {
    throw new LabError(
      401,
      "unauthorized",
      "Sign in via Cloudflare Access (GitHub). Lab calls must carry Cf-Access-Jwt-Assertion."
    );
  }
  // Match on every identity the assertion presented, not just the first.
  // identity.login is only the display name — with no github_login claim it is
  // the email address, while the allowlist may hold the handle or the local
  // part. Checking one string here is what let /v1/research/me say "researcher
  // access" while every lab query returned 403 on the same session.
  const match = await matchAllowEntry(env, identity.candidates || [identity.login]);
  if (!match) {
    await logAbuse(env, {
      action,
      result: "forbidden",
      clientIp: request.headers.get("CF-Connecting-IP") || "0.0.0.0",
      target: identity.login,
      reason: "not_allowlisted",
    });
    throw new LabError(
      403,
      "forbidden",
      "Signed in, but none of the identities this session presents are on the " +
        "researcher allowlist: " +
        (identity.candidates || []).join(", ") +
        ". Quote that list on a research access issue and a maintainer can add " +
        "the right one."
    );
  }

  // The corpus is expensive to assemble; a bored tab on a refresh loop should
  // not be able to spend the Worker's whole KV budget.
  const rl = await consume(
    env,
    `lab:${match.entry.login}`,
    intEnv(env, "RL_LAB_MAX", 20),
    intEnv(env, "RL_LAB_WINDOW_SEC", 300)
  );
  const daily = await consume(
    env,
    `lab_day:${match.entry.login}`,
    intEnv(env, "RL_LAB_DAY_MAX", 50),
    86400
  );
  if (!rl.ok || !daily.ok) {
    throw new LabError(429, "rate_limited", "Lab query rate limit reached.", {
      scope: "lab",
      reset: !rl.ok ? rl.reset : daily.reset,
    });
  }
  return identity;
}

/* ------------------------------------------------------------------ */
/* Corpus loading + normalisation                                      */
/* ------------------------------------------------------------------ */

/**
 * Mirrors the key layout in discovery.js. Duplicated deliberately: the
 * host-detail route reads one record, and paying a full corpus scan to find it
 * would cost hundreds of KV gets for a single lookup.
 */
const HIT_PREFIX = "discovery:hit:";

/**
 * Raw records cached per isolate for a few seconds so a researcher paging
 * through the catalog does not re-read the whole corpus on every request.
 * Exclusions are deliberately *not* baked into the cached value — they are
 * re-applied on every request, so an exclusion filed one second ago suppresses
 * a host immediately instead of waiting for a cache expiry.
 */
const corpusCache = { key: null, rows: null, at: 0 };

async function loadRawCorpus(env, scan) {
  const ttl = intEnv(env, "LAB_CACHE_TTL_SEC", 60) * 1000;
  const now = Date.now();
  if (corpusCache.rows && corpusCache.key === scan && now - corpusCache.at < ttl) {
    return corpusCache.rows;
  }
  const rows = await listHits(env, { limit: scan, sort: "last_seen" });
  corpusCache.key = scan;
  corpusCache.rows = rows;
  corpusCache.at = now;
  return rows;
}

/**
 * Assemble the working corpus.
 *
 * Fails closed on the exclusion list for the same reason the runner does
 * (I-25): an exclusion deletes existing records as well as stopping future
 * probes, and deletion may lag the request. If we cannot prove a host is not
 * inside excluded space, we do not show it.
 */
async function loadCorpus(env, scan) {
  if (!env.KV) {
    throw new LabError(503, "corpus_unavailable", "No corpus store bound to this Worker.");
  }
  let exclusions;
  try {
    exclusions = await loadExclusions(env);
  } catch {
    throw new LabError(
      503,
      "exclusions_unreadable",
      "Exclusion list could not be read, so the corpus is withheld. This fails closed by design (I-25)."
    );
  }

  const raw = await loadRawCorpus(env, scan);
  const rows = [];
  let suppressed = 0;
  for (const record of raw) {
    if (!record || !record.ip) continue;
    if (isExcluded(exclusions, { ip: record.ip, asn: record.asn })) {
      suppressed++;
      continue;
    }
    rows.push(normalizeHost(record));
  }
  return {
    rows,
    scan_cap: scan,
    truncated: raw.length >= scan,
    excluded_suppressed: suppressed,
  };
}

/** Pull a version out of a Shodan-style product banner ("Ollama 0.1.40"). */
function versionFromProduct(product) {
  const m = /(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]+)?)/.exec(String(product || ""));
  return m ? m[1] : null;
}

const OSV_SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z.\-+:]{0,63}$/;

/**
 * Normalise one stored record.
 *
 * Re-verification timestamps are read through aliases because the runner that
 * writes them is landing alongside this module: whichever name it settles on,
 * the lab reports the stored value and falls back to `last_seen` rather than
 * inventing a freshness it cannot support.
 */
function normalizeHost(record) {
  const stacks = (record.stacks && record.stacks.length
    ? record.stacks
    : record.stack
      ? [record.stack]
      : []
  )
    .map((s) => clean(s, 32))
    .filter(Boolean);
  const ports = (record.ports && record.ports.length ? record.ports : record.port ? [record.port] : [])
    .map((p) => Number(p))
    .filter((p) => Number.isInteger(p));

  const product = clean(record.product, 120);
  const explicitVersion = clean(record.version || record.versions?.[stacks[0]], 64);
  const version = explicitVersion || versionFromProduct(product);

  const lastSuccess =
    toMs(record.last_verified_at) ??
    toMs(record.last_success_at) ??
    toMs(record.last_seen);
  const lastAttempt =
    toMs(record.last_probe_at) ?? toMs(record.last_attempt_at) ?? lastSuccess;

  return {
    ip: record.ip,
    ports,
    port: ports[0] ?? null,
    stacks,
    stack: stacks[0] ?? null,
    source: clean(record.source, 48),
    product,
    version,
    version_source: explicitVersion ? "probe" : version ? "index_banner" : null,
    country: clean(record.country, 64),
    // clean() returns null for a value that is truthy but blank once control
    // characters are stripped (I-16: these strings are attacker-controlled), so
    // the uppercase has to be optional or one malformed row 500s every lab route.
    country_code: clean(record.country_code, 4)?.toUpperCase() ?? null,
    city: clean(record.city, 64),
    asn: normAsn(record.asn),
    org: clean(record.org, 96),
    first_seen: record.first_seen || null,
    last_seen: record.last_seen || null,
    times_seen: Number(record.times_seen) || 0,
    // I-26 minimisation: model lists are not part of the record we intend to
    // retain. Legacy rows still carry them, so the lab reports a count and only
    // hands back names when a researcher asks for them explicitly.
    models_count: Array.isArray(record.models) ? record.models.length : 0,
    models_raw: Array.isArray(record.models) ? record.models : [],
    vulns: (Array.isArray(record.vulns) ? record.vulns : []).slice(0, 25).map(normalizeVuln),
    first_seen_ms: toMs(record.first_seen),
    last_seen_ms: toMs(record.last_seen),
    last_success_ms: lastSuccess,
    last_attempt_ms: lastAttempt,
    notified_ms: toMs(record.notified_at || record.disclosure?.notified_at),
    notified_via: clean(record.notified_via || record.disclosure?.route, 64),
  };
}

function normalizeVuln(v) {
  if (typeof v === "string") return { id: clean(v, 48), title: null, severity: null, source: "index" };
  return {
    id: clean(v?.id || v?.cve, 48),
    cve: clean(v?.cve, 48),
    title: clean(v?.title || v?.summary, 200),
    severity: clean(v?.severity, 16),
    source: clean(v?.source, 32) || "index",
  };
}

/* ------------------------------------------------------------------ */
/* Derived state: freshness (I-24), retention (I-26), disclosure (I-27)*/
/* ------------------------------------------------------------------ */

function verification(row, now, env) {
  const sinceSuccess = daysSince(row.last_success_ms, now);
  const sinceAttempt = daysSince(row.last_attempt_ms, now);
  const expiryDays = intEnv(env, "CORPUS_EXPIRY_DAYS", EXPIRY_DAYS);
  const reprobeDays = intEnv(env, "REPROBE_INTERVAL_DAYS", REPROBE_INTERVAL_DAYS);

  let state = "unverified";
  if (sinceSuccess != null) {
    if (sinceSuccess <= reprobeDays) state = "answering";
    else if (sinceSuccess <= expiryDays / 2) state = "stale";
    else if (sinceSuccess <= expiryDays) state = "silent";
    else state = "expired";
  }

  // A host whose last attempt is newer than its last success went quiet at the
  // last success, not at the last attempt — expiry is measured from contact.
  const wentSilentAt =
    row.last_attempt_ms != null &&
    row.last_success_ms != null &&
    row.last_attempt_ms > row.last_success_ms
      ? new Date(row.last_success_ms).toISOString()
      : null;

  return {
    state,
    last_success_at: row.last_success_ms ? new Date(row.last_success_ms).toISOString() : null,
    last_attempt_at: row.last_attempt_ms ? new Date(row.last_attempt_ms).toISOString() : null,
    days_since_success: sinceSuccess,
    days_since_attempt: sinceAttempt,
    silent_since: wentSilentAt,
    // Informational only. Nothing in this module schedules or triggers a probe.
    reprobe_eligible_at: isoPlusDays(row.last_attempt_ms, reprobeDays),
    expires_at: isoPlusDays(row.last_success_ms, expiryDays),
    expired: state === "expired",
    basis:
      "Derived from the stored record. A successful contact resets the clock; expiry is measured from last contact, never from record creation.",
  };
}

/**
 * I-27: a notification attempt plus an elapsed window is the precondition for
 * publishing anything host-identifying. Researchers see the corpus; this flag
 * is what stops a downstream surface treating that as permission to publish.
 */
function disclosure(row, now, env) {
  const windowDays = Math.min(
    90,
    Math.max(1, intEnv(env, "DISCLOSURE_WINDOW_DAYS", DISCLOSURE_WINDOW_DAYS))
  );
  const notified = row.notified_ms;
  const elapsed = notified != null && now - notified >= windowDays * DAY_MS;
  return {
    notified_at: notified ? new Date(notified).toISOString() : null,
    notified_via: row.notified_via,
    window_days: windowDays,
    publishable_at: isoPlusDays(notified, windowDays),
    publishable: !!elapsed,
    reason: notified ? (elapsed ? "window_elapsed" : "window_open") : "no_notification_attempt",
  };
}

/**
 * Host-identifying fields, per I-27.
 *
 * city/org/product are no longer retained on new records (I-26 minimisation),
 * but legacy rows still carry them and normalizeHost still surfaces them, so
 * they stay on this list: a field that is usually absent is not a field that is
 * safe to publish when it is present.
 */
const HOST_IDENTIFYING = ["ip", "city", "org", "product"];

/**
 * Strip host-identifying fields from a lab record. Any surface that is not the
 * gated lab — an export, a public aggregate, a write-up feed — should pass
 * records through this rather than re-deriving the rule (I-14, I-27).
 *
 * Reachable from the catalog route as `?publication=1`, so this is a path that
 * runs and is asserted rather than a helper the first real caller would be
 * trusting sight unseen.
 */
export function redactForPublication(record) {
  if (!record) return record;
  if (record.disclosure?.publishable) return record;
  const out = { ...record };
  for (const field of HOST_IDENTIFYING) delete out[field];
  out.redacted = HOST_IDENTIFYING;
  out.redaction_reason = record.disclosure?.reason || "no_notification_attempt";
  return out;
}

/* ------------------------------------------------------------------ */
/* Filtering                                                           */
/* ------------------------------------------------------------------ */

const SORTS = {
  last_seen: (r) => r.last_seen_ms ?? 0,
  first_seen: (r) => r.first_seen_ms ?? 0,
  times_seen: (r) => r.times_seen,
  ip: (r) => r.ip,
  country: (r) => r.country_code || r.country || "ZZ",
  asn: (r) => r.asn || "",
  stack: (r) => r.stack || "",
  version: (r) => r.version || "",
};

const STATES = new Set(["answering", "stale", "silent", "expired", "unverified"]);

function parseFilters(params) {
  const stacks = parseList(params, "stack").map((s) => s.toLowerCase());
  const countries = parseList(params, "country").map((s) => s.toUpperCase());
  const asns = parseList(params, "asn").map(normAsn);
  const sources = parseList(params, "source").map((s) => s.toLowerCase());
  const states = parseList(params, "state").map((s) => s.toLowerCase());
  for (const s of states) {
    if (!STATES.has(s)) {
      throw badRequest("invalid_parameter", `unknown state '${s}'`, { supported: [...STATES] });
    }
  }

  const cidrRaw = params.get("cidr");
  let cidr = null;
  if (cidrRaw) {
    cidr = parseExclusionEntry(cidrRaw);
    if (!cidr || cidr.type === "asn") {
      throw badRequest("invalid_parameter", "cidr must be an IPv4/IPv6 address or CIDR block");
    }
  }

  return {
    stacks,
    countries,
    asns,
    sources,
    states,
    cidr,
    org: (params.get("org") || "").trim().toLowerCase() || null,
    version: clean(params.get("version"), 64),
    version_prefix: clean(params.get("version_prefix"), 64),
    has_version: params.get("has_version"),
    vuln: (params.get("vuln") || "").trim().toUpperCase() || null,
    q: (params.get("q") || "").trim().toLowerCase() || null,
    first_seen_after: parseDateParam(params, "first_seen_after"),
    first_seen_before: parseDateParam(params, "first_seen_before"),
    last_seen_after: parseDateParam(params, "last_seen_after"),
    last_seen_before: parseDateParam(params, "last_seen_before"),
  };
}

function matches(row, f, state) {
  if (f.stacks.length && !row.stacks.some((s) => f.stacks.includes(s.toLowerCase()))) return false;
  if (f.countries.length) {
    const cc = (row.country_code || "").toUpperCase();
    const name = (row.country || "").toUpperCase();
    if (!f.countries.includes(cc) && !f.countries.includes(name)) return false;
  }
  if (f.asns.length && !f.asns.includes(row.asn)) return false;
  if (f.sources.length && !f.sources.includes((row.source || "").toLowerCase())) return false;
  if (f.states.length && !f.states.includes(state)) return false;
  if (f.cidr && !isExcluded([f.cidr], { ip: row.ip })) return false;
  if (f.org && !(row.org || "").toLowerCase().includes(f.org)) return false;
  if (f.version && (row.version || "") !== f.version) return false;
  if (f.version_prefix && !(row.version || "").startsWith(f.version_prefix)) return false;
  if (f.has_version === "1" && !row.version) return false;
  if (f.has_version === "0" && row.version) return false;
  if (f.vuln && !row.vulns.some((v) => `${v.id || ""} ${v.cve || ""}`.toUpperCase().includes(f.vuln))) {
    return false;
  }
  if (f.q) {
    const hay = [row.org, row.product, row.city, row.country, row.stack].join(" ").toLowerCase();
    if (!hay.includes(f.q)) return false;
  }
  if (f.first_seen_after != null && !(row.first_seen_ms >= f.first_seen_after)) return false;
  if (f.first_seen_before != null && !(row.first_seen_ms <= f.first_seen_before)) return false;
  if (f.last_seen_after != null && !(row.last_seen_ms >= f.last_seen_after)) return false;
  if (f.last_seen_before != null && !(row.last_seen_ms <= f.last_seen_before)) return false;
  return true;
}

function selectRows(corpus, params, env, now) {
  const filters = parseFilters(params);
  const selected = [];
  for (const row of corpus.rows) {
    const v = verification(row, now, env);
    if (matches(row, filters, v.state)) selected.push({ row, verification: v });
  }

  const sortKey = params.get("sort") || "last_seen";
  if (!SORTS[sortKey]) {
    throw badRequest("invalid_parameter", `unknown sort '${sortKey}'`, { supported: Object.keys(SORTS) });
  }
  const dir = (params.get("order") || "desc").toLowerCase() === "asc" ? 1 : -1;
  const key = SORTS[sortKey];
  selected.sort((a, b) => {
    const x = key(a.row);
    const y = key(b.row);
    if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
    return String(x).localeCompare(String(y)) * dir;
  });

  const pageSize = parseIntParam(params, "page_size", DEFAULT_PAGE_SIZE, { min: 1, max: MAX_PAGE_SIZE });
  const page = parseIntParam(params, "page", 1, { min: 1 });
  const start = (page - 1) * pageSize;
  return {
    filters,
    selected,
    page: {
      page,
      page_size: pageSize,
      total: selected.length,
      pages: Math.max(1, Math.ceil(selected.length / pageSize)),
      has_more: start + pageSize < selected.length,
    },
    slice: selected.slice(start, start + pageSize),
  };
}

function scanParam(params) {
  const raw = params.get("limit");
  if (raw == null || raw === "") return DEFAULT_SCAN;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw badRequest("invalid_parameter", "limit must be a positive integer");
  return Math.min(n, MAX_SCAN);
}

function corpusMeta(corpus) {
  return {
    records: corpus.rows.length,
    scan_cap: corpus.scan_cap,
    truncated: corpus.truncated,
    excluded_suppressed: corpus.excluded_suppressed,
    note: corpus.truncated
      ? "The scan cap was reached: this is the most recently indexed slice of the corpus, not all of it. Raise ?limit= (hard max " +
        MAX_SCAN +
        ") or narrow the filters."
      : "Full corpus within the scan cap.",
  };
}

/* ------------------------------------------------------------------ */
/* Record shapes                                                       */
/* ------------------------------------------------------------------ */

function catalogRow(entry, now, env) {
  const { row, verification: v } = entry;
  return {
    // I-14: raw addresses exist here and only here — behind Access plus the
    // researcher allowlist. This shape must never back a public route.
    ip: row.ip,
    ports: row.ports,
    stacks: row.stacks,
    version: row.version,
    version_source: row.version_source,
    product: row.product,
    country: row.country,
    country_code: row.country_code,
    city: row.city,
    asn: row.asn,
    org: row.org,
    source: row.source,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    times_seen: row.times_seen,
    models_count: row.models_count,
    vuln_count: row.vulns.length,
    state: v.state,
    verification: v,
    disclosure: disclosure(row, now, env),
  };
}

/** Findings we can assert from a stored record — never from a fresh probe. */
function confirmedFindings(row) {
  const out = [];
  for (const stack of row.stacks) {
    const svc = SERVICES[stack];
    const finding = svc?.finding;
    out.push({
      service: stack,
      port: row.ports[0] ?? svc?.defaultPort ?? null,
      finding_id: finding?.id || `${stack}-unauth-exposure`,
      title: finding?.title || `Unauthenticated ${stack} surface answered a read`,
      severity: finding?.severity || "high",
      observed_at: row.last_seen,
      basis:
        "Stored exposure record: the listing endpoint answered an unauthenticated read-only GET at observed_at. Impact is described, never demonstrated (I-3).",
    });
  }
  return out;
}

async function osvForRow(row, env, cache) {
  if (!row.version || !OSV_SAFE_VERSION.test(row.version)) return [];
  const out = [];
  for (const stack of row.stacks) {
    const pkg = OSV_PACKAGES[stack];
    if (!pkg) continue;
    const key = `${stack}@${row.version}`;
    if (!cache.map.has(key)) {
      if (cache.used >= cache.cap) {
        cache.exhausted = true;
        continue;
      }
      cache.used += 1;
      cache.map.set(key, await queryOsv(pkg, row.version, env));
    }
    for (const v of cache.map.get(key) || []) {
      out.push({ ...v, service: stack, matched_on: row.version });
    }
  }
  return out;
}

function validationRow(entry, now, env, osv) {
  const { row, verification: v } = entry;
  return {
    ip: row.ip,
    stacks: row.stacks,
    ports: row.ports,
    version_observed: row.version,
    version_source: row.version_source,
    confirmed: confirmedFindings(row),
    advisories: row.stacks.flatMap((stack) => matchAdvisories({ stack, exposed: true })),
    vulns_indexed: row.vulns,
    osv: osv || [],
    verification: v,
    disclosure: disclosure(row, now, env),
  };
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

const LAB_HEADERS = {
  // Gated researcher data: never cached by an intermediary, never sniffed.
  "Cache-Control": "no-store, private",
  "X-Content-Type-Options": "nosniff",
};

function labJson(payload, status, request, env) {
  return json(payload, status, request, env, LAB_HEADERS);
}

function envelope(identity, corpus) {
  return {
    login: identity.login,
    generated_at: new Date().toISOString(),
    corpus: corpusMeta(corpus),
    untrusted_fields: UNTRUSTED_FIELDS,
    render_note:
      "Fields listed in untrusted_fields were produced by probed hosts and are attacker-controlled (I-16). Escape them at render time.",
  };
}

/**
 * GET /v1/research/lab/catalog
 * Filter/sort/paginate the exposed-host corpus. Returns raw addresses; gated.
 */
export async function handleLabCatalog(request, env) {
  return guard(request, env, "lab_catalog", async (identity) => {
    const params = new URL(request.url).searchParams;
    const now = Date.now();
    const corpus = await loadCorpus(env, scanParam(params));
    const { filters, page, slice } = selectRows(corpus, params, env, now);
    // I-27's rule, applied rather than described. Off by default because a
    // researcher working a disclosure needs the address; on request this is the
    // shape that may leave the lab, and it is derived here so a downstream
    // surface never has to re-implement "which fields identify a host".
    const publication = params.get("publication") === "1";
    const rows = slice.map((entry) => catalogRow(entry, now, env));
    return labJson(
      {
        ...envelope(identity, corpus),
        filters: describeFilters(filters, params),
        page,
        publication_redacted: publication,
        hosts: publication ? rows.map(redactForPublication) : rows,
        note: publication
          ? "Redacted for publication (I-27): host-identifying fields are stripped from every host whose disclosure window has not elapsed."
          : "Addresses in this payload are researcher-gated (I-14) and are not cleared for publication — check disclosure.publishable per host (I-27).",
        limitations: LIMITATIONS,
      },
      200,
      request,
      env
    );
  });
}

/**
 * GET /v1/research/lab/map
 * Aggregates and cross-tabs over the same filtered set. Counts only — this
 * payload carries no addresses even though it is gated.
 */
export async function handleLabMap(request, env) {
  return guard(request, env, "lab_map", async (identity) => {
    const params = new URL(request.url).searchParams;
    const now = Date.now();
    const corpus = await loadCorpus(env, scanParam(params));
    const { filters, selected } = selectRows(corpus, params, env, now);
    const rows = selected.map((e) => e.row);
    const states = selected.map((e) => e.verification.state);

    const live = await getLiveStats(env);
    const bucket = params.get("bucket") || "week";
    if (!["day", "week", "month"].includes(bucket)) {
      throw badRequest("invalid_parameter", "bucket must be day, week or month");
    }

    const byAsn = countBy(rows, (r) => r.asn, {
      limit: 25,
      extra: (group) => ({
        org: mode(group.map((r) => r.org)),
        countries: [...new Set(group.map((r) => r.country_code).filter(Boolean))].slice(0, 5),
        stacks: [...new Set(group.flatMap((r) => r.stacks))].slice(0, 5),
      }),
    });

    return labJson(
      {
        ...envelope(identity, corpus),
        filters: describeFilters(filters, params),
        totals: {
          hosts: rows.length,
          hosts_with_version: rows.filter((r) => r.version).length,
          distinct_countries: new Set(rows.map((r) => r.country_code || r.country).filter(Boolean)).size,
          distinct_asns: new Set(rows.map((r) => r.asn).filter(Boolean)).size,
          host_stack_pairs: rows.reduce((n, r) => n + r.stacks.length, 0),
        },
        // Spec §4: three provenance-tagged numbers, never summed into one.
        provenance: {
          archive_snapshot: {
            hosts: parseInt(env.SNAPSHOT_HOSTS || "0", 10) || 0,
            source: "filtered archive-era catalog, counted not probed",
          },
          indexed_observed: {
            hosts: rows.length,
            source: "public index records held in our corpus",
          },
          reverified: {
            hosts: selected.filter((e) => e.verification.state === "answering").length,
            window_days: intEnv(env, "REPROBE_INTERVAL_DAYS", REPROBE_INTERVAL_DAYS),
            source: "read-only GET by us, within the re-probe interval",
          },
        },
        by_stack: countBy(rows, (r) => r.stacks, { limit: 25 }),
        by_country: countBy(rows, (r) => r.country_code || r.country, { limit: 50 }),
        by_asn: byAsn,
        by_org: countBy(rows, (r) => r.org, { limit: 25 }),
        by_version: countBy(rows, (r) => (r.version ? `${r.stack || "?"} ${r.version}` : null), { limit: 25 }),
        by_source: countBy(rows, (r) => r.source, { limit: 25 }),
        by_state: countBy(selected, (e) => e.verification.state, { limit: 10 }),
        crosstab: {
          stack_x_country: crossTab(rows, (r) => r.stacks, (r) => r.country_code || r.country),
          stack_x_asn: crossTab(rows, (r) => r.stacks, (r) => r.asn),
          version_x_stack: crossTab(rows, (r) => r.version, (r) => r.stacks),
        },
        exposure_rate_by_stack: exposureRates(live),
        timeline: {
          bucket,
          first_seen: timeline(rows, (r) => r.first_seen_ms, bucket),
          last_seen: timeline(rows, (r) => r.last_seen_ms, bucket),
        },
        state_note:
          "answering = successful contact inside the re-probe interval (I-24); silent/expired are measured from last contact (I-26).",
        limitations: LIMITATIONS,
      },
      200,
      request,
      env
    );
  });
}

/**
 * GET /v1/research/lab/validation
 * What we can actually stand behind per host: confirmed findings, observed
 * version, matched vulns, and how fresh the last successful contact is.
 * `?osv=1` adds live OSV.dev lookups (capped) on top of indexed vulns.
 */
export async function handleLabValidation(request, env) {
  return guard(request, env, "lab_validation", async (identity) => {
    const params = new URL(request.url).searchParams;
    const now = Date.now();
    const corpus = await loadCorpus(env, scanParam(params));
    const { filters, page, slice, selected } = selectRows(corpus, params, env, now);

    const cache = { map: new Map(), used: 0, cap: OSV_LOOKUP_CAP, exhausted: false };
    const wantOsv = params.get("osv") === "1";
    const hosts = [];
    for (const entry of slice) {
      const osv = wantOsv ? await osvForRow(entry.row, env, cache) : null;
      hosts.push(validationRow(entry, now, env, osv));
    }

    return labJson(
      {
        ...envelope(identity, corpus),
        filters: describeFilters(filters, params),
        page,
        summary: {
          by_state: countBy(selected, (e) => e.verification.state, { limit: 10 }).top,
          with_version: selected.filter((e) => e.row.version).length,
          without_version: selected.filter((e) => !e.row.version).length,
          with_indexed_vulns: selected.filter((e) => e.row.vulns.length).length,
          notified: selected.filter((e) => e.row.notified_ms != null).length,
          publishable: selected.filter((e) => disclosure(e.row, now, env).publishable).length,
        },
        osv: {
          requested: wantOsv,
          lookups_used: cache.used,
          lookup_cap: cache.cap,
          truncated: cache.exhausted,
          note: "OSV.dev is queried with a version string only. It is a vulnerability database, not a probed host.",
        },
        hosts,
        caveats: [
          "Confirmed means a stored record says an unauthenticated read-only GET was answered at that time. It is not a re-test, and nothing here re-probes (I-20).",
          "We report that an endpoint answers unauthenticated requests. We never send one to prove impact (I-3).",
          "An OSV match is version-string inference, not proof the host is vulnerable or unpatched.",
        ],
        limitations: LIMITATIONS,
      },
      200,
      request,
      env
    );
  });
}

/**
 * GET /v1/research/lab/host?ip=<literal>
 * One assembled record. Reads stored data only.
 */
export async function handleLabHost(request, env) {
  return guard(request, env, "lab_host", async (identity) => {
    const params = new URL(request.url).searchParams;
    const ip = String(params.get("ip") || "").trim();
    if (!ip) throw badRequest("ip_required", "Pass ?ip= a literal address from the catalog.");
    if (!isIpLiteral(ip)) {
      throw badRequest("invalid_ip", "Only literal IPv4/IPv6 addresses are accepted.");
    }
    if (!env.KV) throw new LabError(503, "corpus_unavailable", "No corpus store bound to this Worker.");

    let exclusions;
    try {
      exclusions = await loadExclusions(env);
    } catch {
      throw new LabError(
        503,
        "exclusions_unreadable",
        "Exclusion list could not be read, so the record is withheld. This fails closed by design (I-25)."
      );
    }

    const stored = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
    if (!stored) throw new LabError(404, "not_found", "No record for that address in the corpus.");

    const row = normalizeHost(stored);
    if (isExcluded(exclusions, { ip: row.ip, asn: row.asn })) {
      // The operator asked to be left alone; the record is queued for deletion
      // and is not shown in the meantime.
      throw new LabError(
        403,
        "record_excluded",
        "This address space is on the exclusion list. The record is withheld and scheduled for deletion."
      );
    }

    const now = Date.now();
    const v = verification(row, now, env);
    const cache = { map: new Map(), used: 0, cap: 4, exhausted: false };
    const osv = await osvForRow(row, env, cache);
    const includeModels = params.get("include_models") === "1";

    return labJson(
      {
        login: identity.login,
        generated_at: new Date().toISOString(),
        untrusted_fields: UNTRUSTED_FIELDS,
        render_note:
          "Fields listed in untrusted_fields were produced by this host and are attacker-controlled (I-16). Escape them at render time.",
        host: {
          ip: row.ip,
          ports: row.ports,
          stacks: row.stacks,
          source: row.source,
          first_seen: row.first_seen,
          last_seen: row.last_seen,
          times_seen: row.times_seen,
          network: {
            asn: row.asn,
            org: row.org,
            country: row.country,
            country_code: row.country_code,
            city: row.city,
          },
          version: {
            observed: row.version,
            source: row.version_source,
            banner: row.product,
          },
          models_count: row.models_count,
          // I-26: names are content beyond what the finding requires, so they
          // are opt-in and capped rather than part of the default record.
          models: includeModels
            ? row.models_raw.slice(0, 25).map((m) => clean(m?.name || m?.model || m, 96)).filter(Boolean)
            : undefined,
        },
        findings: {
          confirmed: confirmedFindings(row),
          advisories: row.stacks.flatMap((stack) => matchAdvisories({ stack, exposed: true })),
          vulns_indexed: row.vulns,
          osv,
        },
        verification: v,
        retention: {
          expires_at: v.expires_at,
          policy_days: intEnv(env, "CORPUS_EXPIRY_DAYS", EXPIRY_DAYS),
          retained_fields: [
            "address",
            "port",
            "service",
            "version string",
            "first/last seen",
            "geo/ASN",
          ],
          note: "I-26: no job records, no page bodies, no content beyond what the finding requires. Expiry runs from last successful contact.",
        },
        disclosure: disclosure(row, now, env),
        remediation: row.stacks.flatMap((stack) => SERVICES[stack]?.remediation || []),
      },
      200,
      request,
      env
    );
  });
}

/* ------------------------------------------------------------------ */
/* Aggregation helpers                                                 */
/* ------------------------------------------------------------------ */

function mode(values) {
  const counts = new Map();
  for (const v of values) {
    if (!v) continue;
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  let best = null;
  let bestN = 0;
  for (const [k, n] of counts) {
    if (n > bestN) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/**
 * Exposure rate per stack, from the check ledger rather than the corpus: the
 * corpus only holds hosts that were exposed, so it has no denominator of its
 * own and any "rate" derived from it would be 100% by construction.
 */
function exposureRates(live) {
  const by = live.by_service || {};
  const rows = Object.entries(by).map(([service, s]) => ({
    service,
    checks: s.checks || 0,
    detected: s.detected || 0,
    exposed: s.exposed || 0,
    exposed_of_detected: s.detected ? Math.round((s.exposed / s.detected) * 1000) / 10 : null,
    exposed_of_checked: s.checks ? Math.round((s.exposed / s.checks) * 1000) / 10 : null,
  }));
  return {
    rows: rows.sort((a, b) => b.checks - a.checks),
    denominator:
      "Voluntary self-checks plus re-verification attempts recorded by this Worker — not a random sample of the internet (Q-3).",
  };
}

function bucketStart(ms, bucket) {
  const d = new Date(ms);
  if (bucket === "month") return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  const day = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  if (bucket === "day") return day;
  // Week buckets start Monday.
  const dow = (new Date(day).getUTCDay() + 6) % 7;
  return day - dow * DAY_MS;
}

function timeline(rows, tsFn, bucket, maxBuckets = 400) {
  const counts = new Map();
  for (const row of rows) {
    const ms = tsFn(row);
    if (ms == null) continue;
    const b = bucketStart(ms, bucket);
    counts.set(b, (counts.get(b) || 0) + 1);
  }
  const ordered = [...counts.entries()].sort((a, b) => a[0] - b[0]).slice(-maxBuckets);
  let cumulative = 0;
  return ordered.map(([b, hosts]) => {
    cumulative += hosts;
    return { bucket: new Date(b).toISOString().slice(0, 10), hosts, cumulative };
  });
}

function describeFilters(filters, params) {
  const applied = {};
  for (const [k, v] of Object.entries(filters)) {
    if (v == null) continue;
    if (Array.isArray(v) && !v.length) continue;
    applied[k] = k.endsWith("_after") || k.endsWith("_before") ? new Date(v).toISOString() : v;
  }
  return {
    applied,
    sort: params.get("sort") || "last_seen",
    order: (params.get("order") || "desc").toLowerCase() === "asc" ? "asc" : "desc",
    supported: {
      filters: [
        "stack",
        "country",
        "asn",
        "org",
        "source",
        "state",
        "cidr",
        "version",
        "version_prefix",
        "has_version",
        "vuln",
        "q",
        "first_seen_after",
        "first_seen_before",
        "last_seen_after",
        "last_seen_before",
      ],
      sorts: Object.keys(SORTS),
      states: [...STATES],
    },
  };
}

/* ------------------------------------------------------------------ */
/* Routing                                                             */
/* ------------------------------------------------------------------ */

async function guard(request, env, action, fn) {
  try {
    const identity = await gate(request, env, action);
    return await fn(identity);
  } catch (err) {
    if (err instanceof LabError) {
      return labJson({ error: err.code, message: err.message, ...(err.extra || {}) }, err.status, request, env);
    }
    throw err;
  }
}

export const LAB_ROUTES = [
  { method: "GET", path: `${ROUTE_PREFIX}/catalog`, handler: handleLabCatalog },
  { method: "GET", path: `${ROUTE_PREFIX}/map`, handler: handleLabMap },
  { method: "GET", path: `${ROUTE_PREFIX}/validation`, handler: handleLabValidation },
  { method: "GET", path: `${ROUTE_PREFIX}/host`, handler: handleLabHost },
];

/**
 * Single mount point for index.js: returns a Response for anything under
 * /v1/research/lab, or null when the path belongs to another handler.
 * Method and path checks live here so an unknown lab path cannot fall through
 * to a route that is gated differently.
 */
export async function routeLab(request, env) {
  const path = new URL(request.url).pathname.replace(/\/+$/, "") || "/";
  if (path !== ROUTE_PREFIX && !path.startsWith(`${ROUTE_PREFIX}/`)) return null;

  const match = LAB_ROUTES.find((r) => r.path === path);
  if (!match) {
    return labJson(
      { error: "not_found", routes: LAB_ROUTES.map((r) => `${r.method} ${r.path}`) },
      404,
      request,
      env
    );
  }
  if (request.method !== match.method) {
    // The lab is read-only by construction: there is no write path to reach.
    return labJson({ error: "method_not_allowed", allow: match.method }, 405, request, env);
  }
  return match.handler(request, env);
}
