/**
 * Strongly consistent discovery/check control plane.
 *
 * One SQLite-backed Durable Object owns every decision that can permit target
 * traffic. The public Worker is its only caller; no route is attached directly
 * to this class. Production traffic kill switches remain outside it.
 */
import { addressBucket, canonicalizeIp, isPrivateOrLocal } from "./lib/check.js";
import { isExcluded, parseExclusionEntry } from "./lib/exclusions.js";
import { resolvePort } from "./lib/services.js";

const DAY_MS = 86_400_000;
const ACTIVE_COOLDOWN_MS = 14 * DAY_MS;
const PROVENANCE_MAX_AGE_MS = 7 * DAY_MS;
const PERMIT_TTL_MS = 60_000;
const HOST_RETENTION_MS = 180 * DAY_MS;
const ATTEMPT_RETENTION_MS = 90 * DAY_MS;
const MAX_PAGE = 500;
const UNKNOWN_ASN = "AS-UNKNOWN";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function rows(cursor) {
  return cursor?.toArray ? cursor.toArray() : [];
}

function one(cursor) {
  return rows(cursor)[0] || null;
}

function normalizeAsn(value) {
  const match = /^(?:as)?(\d{1,10})$/i.exec(String(value || "").trim());
  if (!match) return UNKNOWN_ASN;
  const n = Number(match[1]);
  return Number.isInteger(n) && n >= 0 && n <= 4_294_967_295
    ? `AS${n}`
    : UNKNOWN_ASN;
}

function parseTime(value, fallback = null) {
  if (Number.isFinite(value)) return Math.floor(value);
  const parsed = Date.parse(value || "");
  return Number.isFinite(parsed) ? parsed : fallback;
}

function boundedText(value, max, pattern = null) {
  if (value == null || value === "") return null;
  const text = String(value).trim().slice(0, max);
  return !text || (pattern && !pattern.test(text)) ? null : text;
}

function uniqNumbers(values) {
  return [...new Set((values || []).map(Number).filter(
    (value) => Number.isInteger(value) && value > 0 && value <= 65_535
  ))].sort((a, b) => a - b).slice(0, 16);
}

function uniqStacks(values) {
  return [...new Set((values || []).map(
    (value) => boundedText(value, 32, /^[a-z0-9_-]+$/i)
  ).filter(Boolean))].sort().slice(0, 32);
}

function decodeAttemptCursor(value) {
  try {
    const parsed = JSON.parse(String(value || ""));
    return Array.isArray(parsed) && parsed.length === 2
      ? [String(parsed[0] || ""), String(parsed[1] || "")]
      : ["", ""];
  } catch {
    return ["", ""];
  }
}

function encodeAttemptCursor(row) {
  return row ? JSON.stringify([row.ip, row.purpose]) : "";
}

function normalizeHostRecord(input, now = Date.now()) {
  const ip = canonicalizeIp(input?.ip);
  if (!ip || isPrivateOrLocal(ip)) return { error: "target_not_public_unicast" };
  const firstSeen = parseTime(input.first_seen ?? input.first_seen_at, now);
  const lastSeen = parseTime(input.last_seen ?? input.last_seen_at, null);
  const base = lastSeen ?? firstSeen;
  const indexObservedAt = parseTime(input.index_observed_at, null);
  const ports = uniqNumbers([
    ...(Array.isArray(input.ports) ? input.ports : []),
    input.port,
  ]);
  const stacks = uniqStacks([
    ...(Array.isArray(input.stacks) ? input.stacks : []),
    input.stack,
  ]);
  const record = {
    ip,
    port: ports[0] || null,
    ports,
    stack: stacks[0] || null,
    stacks,
    version: boundedText(input.version, 64),
    first_seen: new Date(firstSeen).toISOString(),
    last_seen: lastSeen == null ? null : new Date(lastSeen).toISOString(),
    source: boundedText(input.source, 160) || "migration",
    index_observed_at: indexObservedAt == null ? null : new Date(indexObservedAt).toISOString(),
    country: boundedText(input.country, 64),
    country_code: boundedText(input.country_code, 2, /^[A-Z]{2}$/i)?.toUpperCase() || null,
    asn: normalizeAsn(input.asn),
  };
  return {
    record,
    ip,
    asn: record.asn,
    countryCode: record.country_code,
    firstSeen,
    lastSeen,
    expiresAt: base + HOST_RETENTION_MS,
  };
}

function ruleMatches(ruleType, ruleValue, row) {
  return isExcluded(
    [{ type: ruleType, value: ruleValue, active: true }],
    { ip: row.ip, asn: row.asn }
  );
}

function validProvenance(provenance, now, ip, asn) {
  if (!provenance || provenance.kind !== "public_index") return false;
  if (!new Set(["shodan", "censys"]).has(provenance.source)) return false;
  if (canonicalizeIp(provenance.ip) !== ip) return false;
  if (normalizeAsn(provenance.asn) !== asn || asn === UNKNOWN_ASN) return false;
  const observed = Date.parse(provenance.observed_at || "");
  return Number.isFinite(observed) && observed <= now && now - observed <= PROVENANCE_MAX_AGE_MS;
}

function ratePolicy(purpose, asn) {
  if (purpose === "owned_canary") {
    return [["owned_canary_10m", 3, 10 * 60_000]];
  }
  if (purpose === "hosted_self") {
    return [
      ["hosted_ip_15m", 3, 15 * 60_000],
      ["hosted_ip_day", 12, DAY_MS],
      ["hosted_global_day", 800, DAY_MS],
    ];
  }
  if (asn === UNKNOWN_ASN) {
    return [
      ["active_unknown_asn", 1, 5 * 60_000],
      ["active_global_minute", 12, 60_000],
    ];
  }
  return [
    ["active_net", 1, 60_000],
    ["active_asn", 2, 60_000],
    ["active_global_minute", 12, 60_000],
  ];
}

export class DiscoveryControlPlane {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;
    if (env.ENVIRONMENT === "production" && env.CONTROL_PLANE_READY === "true") {
      // Production cutover is complete and the single named object is already
      // migrated. Do not execute even no-op DDL here: Cloudflare charges those
      // statements against the free-tier row-write budget and can make every
      // read fail after a new Worker version instantiates the object.
      return;
    }
    let schemaReady = true;
    try {
      // DDL and INSERT OR IGNORE consume the Durable Object row-write budget
      // even when the logical schema is unchanged. A new Worker version can
      // reinstantiate this object many times, so probe the existing schema with
      // a read and initialize only a genuinely empty object.
      this.sql.exec("SELECT value FROM control_meta LIMIT 1");
    } catch {
      schemaReady = false;
    }
    if (!schemaReady) {
      this.sql.exec(`
      CREATE TABLE IF NOT EXISTS exclusions (
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        meta_json TEXT,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (type, value)
      );
      CREATE TABLE IF NOT EXISTS attempts (
        ip TEXT NOT NULL,
        purpose TEXT NOT NULL,
        asn TEXT NOT NULL,
        net_bucket TEXT NOT NULL,
        lease_id TEXT NOT NULL UNIQUE,
        lease_state TEXT NOT NULL,
        last_attempt_at INTEGER NOT NULL,
        next_eligible_at INTEGER NOT NULL,
        provenance_json TEXT,
        outcome TEXT,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (ip, purpose)
      );
      CREATE INDEX IF NOT EXISTS attempts_due ON attempts(purpose, next_eligible_at, ip);
      CREATE INDEX IF NOT EXISTS attempts_asn ON attempts(asn, ip);

      CREATE TABLE IF NOT EXISTS permits (
        id TEXT PRIMARY KEY,
        lease_id TEXT NOT NULL,
        ip TEXT NOT NULL,
        asn TEXT NOT NULL,
        service TEXT NOT NULL,
        port INTEGER NOT NULL,
        purpose TEXT NOT NULL,
        remaining INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS permits_expiry ON permits(expires_at);

      CREATE TABLE IF NOT EXISTS rate_events (
        scope TEXT NOT NULL,
        bucket_key TEXT NOT NULL,
        at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS rate_window ON rate_events(scope, bucket_key, at);

      CREATE TABLE IF NOT EXISTS hosts (
        ip TEXT PRIMARY KEY,
        asn TEXT NOT NULL,
        country_code TEXT,
        record_json TEXT NOT NULL,
        first_seen_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS hosts_expiry ON hosts(expires_at, ip);
      CREATE INDEX IF NOT EXISTS hosts_asn ON hosts(asn, ip);

      CREATE TABLE IF NOT EXISTS purge_jobs (
        id TEXT PRIMARY KEY,
        rule_type TEXT NOT NULL,
        rule_value TEXT NOT NULL,
        status TEXT NOT NULL,
        host_cursor TEXT,
        attempt_cursor TEXT,
        verification_pass INTEGER NOT NULL DEFAULT 0,
        matched INTEGER NOT NULL DEFAULT 0,
        deleted INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        completed_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS aggregate_generations (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        cursor TEXT,
        started_at INTEGER NOT NULL,
        completed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS aggregate_counts (
        generation_id TEXT NOT NULL,
        dimension TEXT NOT NULL,
        bucket TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (generation_id, dimension, bucket)
      );
      CREATE TABLE IF NOT EXISTS control_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS purge_status ON purge_jobs(status, created_at);
    `);
      this.sql.exec(
        "INSERT OR IGNORE INTO control_meta(key, value) VALUES ('corpus_epoch', '0')"
      );
    }
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method === "GET" && path === "/health") return this.health();
    if (request.method === "GET" && path === "/hosts/page") {
      return this.listHosts(new URL(request.url).searchParams);
    }
    if (request.method === "GET" && path === "/attempts/page") {
      return this.listAttempts(new URL(request.url).searchParams);
    }
    if (request.method === "GET" && path === "/hosts/expiring") {
      return this.listExpiringHosts(new URL(request.url).searchParams);
    }
    if (request.method === "GET" && path === "/migration/status") return this.migrationStatus();
    if (request.method === "GET" && path === "/purge/status") {
      return this.purgeStatus(new URL(request.url).searchParams.get("id"));
    }
    if (request.method === "GET" && path === "/aggregates/current") return this.currentAggregates();
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_json" }, 400);
    }

    if (path === "/exclusions/add") return this.addExclusions(body);
    if (path === "/lease/acquire") return this.acquireLease(body);
    if (path === "/permit/consume") return this.consumePermit(body);
    if (path === "/lease/complete") return this.completeLease(body);
    if (path === "/hosts/upsert") return this.upsertHosts(body);
    if (path === "/hosts/retire") return this.retireHosts(body);
    if (path === "/attempts/import") return this.importAttempts(body);
    if (path === "/migration/checkpoint") return this.migrationCheckpoint(body);
    if (path === "/migration/complete") return this.completeMigration(body);
    if (path === "/purge/resume") return this.resumePurge(body);
    if (path === "/retention/run") return this.runRetention(body);
    if (path === "/reconcile/run") return this.runReconciliation(body);
    return json({ error: "not_found" }, 404);
  }

  health() {
    const hosts = one(this.sql.exec("SELECT COUNT(*) AS n FROM hosts"))?.n || 0;
    const attempts = one(this.sql.exec("SELECT COUNT(*) AS n FROM attempts"))?.n || 0;
    const exclusions = one(
      this.sql.exec("SELECT COUNT(*) AS n FROM exclusions WHERE active = 1")
    )?.n || 0;
    const pendingPurges = one(this.sql.exec(
      "SELECT COUNT(*) AS n FROM purge_jobs WHERE status != 'complete'"
    ))?.n || 0;
    const migration = this.meta("migration_complete") === "true";
    const generation = this.meta("current_aggregate_generation");
    return json({
      ok: true,
      schema: 2,
      hosts,
      attempts,
      exclusions,
      pending_purges: pendingPurges,
      migration_complete: migration,
      aggregate_generation: generation || null,
      ready: migration && !!generation && Number(pendingPurges) === 0,
    });
  }

  meta(key) {
    return one(this.sql.exec("SELECT value FROM control_meta WHERE key = ?", key))?.value ?? null;
  }

  setMeta(key, value) {
    this.sql.exec(
      `INSERT INTO control_meta(key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      key,
      String(value)
    );
  }

  bumpCorpusEpoch() {
    const epoch = Number(this.meta("corpus_epoch") || 0) + 1;
    this.setMeta("corpus_epoch", epoch);
    return epoch;
  }

  activeExclusions() {
    return rows(this.sql.exec(
      "SELECT type, value, active FROM exclusions WHERE active = 1 ORDER BY type, value"
    )).map((row) => ({ ...row, active: row.active === 1 }));
  }

  addExclusions(body) {
    const entries = Array.isArray(body.entries) ? body.entries : [];
    const accepted = [];
    const rejected = [];
    const purgeJobs = [];
    const now = Date.now();
    for (const input of entries) {
      const supplied = typeof input === "object" ? input?.value : input;
      const parsed = parseExclusionEntry(supplied);
      if (!parsed || (input?.type && input.type !== parsed.type)) {
        rejected.push({ input: String(supplied ?? "").slice(0, 64), reason: "unparseable" });
        continue;
      }
      this.sql.exec(
        `INSERT INTO exclusions(type, value, active, meta_json, created_at)
         VALUES (?, ?, 1, ?, ?)
         ON CONFLICT(type, value) DO UPDATE SET active = 1, meta_json = excluded.meta_json`,
        parsed.type,
        parsed.value,
        JSON.stringify(body.meta || {}),
        now
      );
      accepted.push(parsed);
      let job = one(this.sql.exec(
        `SELECT id, status FROM purge_jobs
         WHERE rule_type = ? AND rule_value = ?
         ORDER BY created_at DESC LIMIT 1`,
        parsed.type,
        parsed.value
      ));
      if (!job) {
        const id = crypto.randomUUID();
        this.sql.exec(
          `INSERT INTO purge_jobs(id, rule_type, rule_value, status, created_at, updated_at)
           VALUES (?, ?, ?, 'hosts', ?, ?)`,
          id,
          parsed.type,
          parsed.value,
          now,
          now
        );
        job = { id, status: "hosts" };
      }
      purgeJobs.push(job);
    }
    return json({
      ok: rejected.length === 0,
      accepted,
      rejected,
      purge_jobs: purgeJobs,
      total: this.activeExclusions().length,
    });
  }

  listHosts(params) {
    const cursor = canonicalizeIp(params.get("cursor")) || "";
    const limit = Math.max(1, Math.min(Number(params.get("limit")) || 100, MAX_PAGE));
    const page = rows(this.sql.exec(
      `SELECT ip, record_json, expires_at, updated_at FROM hosts
       WHERE ip > ? ORDER BY ip LIMIT ?`,
      cursor,
      limit
    ));
    const records = page.map((row) => JSON.parse(row.record_json));
    return json({
      ok: true,
      records,
      next_cursor: page.length === limit ? page[page.length - 1].ip : null,
      complete: page.length < limit,
    });
  }

  listAttempts(params) {
    const cursor = canonicalizeIp(params.get("cursor")) || "";
    const limit = Math.max(1, Math.min(Number(params.get("limit")) || 100, MAX_PAGE));
    const page = rows(this.sql.exec(
      `SELECT ip, asn, last_attempt_at, next_eligible_at, outcome, updated_at
       FROM attempts
       WHERE purpose = 'active_discovery' AND ip > ?
       ORDER BY ip LIMIT ?`,
      cursor,
      limit
    ));
    return json({
      ok: true,
      attempts: page.map((row) => ({
        ip: row.ip,
        asn: row.asn,
        last_attempt_at: new Date(Number(row.last_attempt_at)).toISOString(),
        next_eligible_at: new Date(Number(row.next_eligible_at)).toISOString(),
        outcome: row.outcome || null,
        updated_at: new Date(Number(row.updated_at)).toISOString(),
      })),
      next_cursor: page.length === limit ? page[page.length - 1].ip : null,
      complete: page.length < limit,
    });
  }

  listExpiringHosts(params) {
    const cursor = canonicalizeIp(params.get("cursor")) || "";
    const limit = Math.max(1, Math.min(Number(params.get("limit")) || 100, MAX_PAGE));
    const now = Number(params.get("now")) || Date.now();
    const askedDays = Number(params.get("days"));
    const dueDays = Number.isFinite(askedDays) && askedDays > 0
      ? Math.min(askedDays, 179)
      : 179;
    const cutoff = now - dueDays * DAY_MS;
    const page = rows(this.sql.exec(
      `SELECT ip, record_json, first_seen_at, last_seen_at
       FROM hosts
       WHERE ip > ? AND COALESCE(NULLIF(last_seen_at, 0), first_seen_at) <= ?
       ORDER BY ip LIMIT ?`,
      cursor,
      cutoff,
      limit
    ));
    return json({
      ok: true,
      due_days: dueDays,
      cutoff: new Date(cutoff).toISOString(),
      due: page.map((row) => {
        const record = JSON.parse(row.record_json);
        const seen = Number(row.last_seen_at) || Number(row.first_seen_at);
        return {
          ...record,
          age_days: Math.floor((now - seen) / DAY_MS),
          final_verification: true,
        };
      }),
      next_cursor: page.length === limit ? page[page.length - 1].ip : null,
      complete: page.length < limit,
    });
  }

  upsertHosts(body) {
    const records = Array.isArray(body.records) ? body.records.slice(0, MAX_PAGE) : [];
    if (!records.length) return json({ ok: false, error: "records_required" }, 400);
    const now = Number.isFinite(body.now) ? Math.floor(body.now) : Date.now();
    const accepted = [];
    const rejected = [];
    this.ctx.storage.transactionSync(() => {
      for (const input of records) {
        const normalized = normalizeHostRecord(input, now);
        if (normalized.error) {
          rejected.push({ ip: String(input?.ip || "").slice(0, 64), error: normalized.error });
          continue;
        }
        if (isExcluded(this.activeExclusions(), { ip: normalized.ip, asn: normalized.asn })) {
          rejected.push({ ip: normalized.ip, error: "target_excluded" });
          continue;
        }
        const prior = one(this.sql.exec(
          "SELECT record_json, first_seen_at, last_seen_at FROM hosts WHERE ip = ?",
          normalized.ip
        ));
        let next = normalized;
        if (prior) {
          const old = JSON.parse(prior.record_json);
          const mergedPorts = uniqNumbers([...(old.ports || []), ...(normalized.record.ports || [])]);
          const mergedStacks = uniqStacks([...(old.stacks || []), ...(normalized.record.stacks || [])]);
          const firstSeen = Math.min(Number(prior.first_seen_at), normalized.firstSeen);
          const oldLast = Number(prior.last_seen_at) || null;
          const lastSeen = Math.max(oldLast || 0, normalized.lastSeen || 0) || null;
          const supplied = Object.fromEntries(
            Object.entries(normalized.record).filter(([, value]) => value != null)
          );
          const record = {
            ...old,
            ...supplied,
            port: mergedPorts[0] || null,
            ports: mergedPorts,
            stack: mergedStacks[0] || null,
            stacks: mergedStacks,
            first_seen: new Date(firstSeen).toISOString(),
            last_seen: lastSeen == null ? null : new Date(lastSeen).toISOString(),
            index_observed_at: [old.index_observed_at, normalized.record.index_observed_at]
              .filter(Boolean)
              .sort()
              .at(-1) || null,
          };
          next = {
            ...normalized,
            record,
            asn: normalized.asn === UNKNOWN_ASN ? normalizeAsn(old.asn) : normalized.asn,
            countryCode: normalized.countryCode || old.country_code || null,
            firstSeen,
            lastSeen,
            expiresAt: (lastSeen ?? firstSeen) + HOST_RETENTION_MS,
          };
        }
        this.sql.exec(
          `INSERT INTO hosts(ip, asn, country_code, record_json, first_seen_at,
             last_seen_at, expires_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
             asn = excluded.asn,
             country_code = excluded.country_code,
             record_json = excluded.record_json,
             first_seen_at = excluded.first_seen_at,
             last_seen_at = excluded.last_seen_at,
             expires_at = excluded.expires_at,
             updated_at = excluded.updated_at`,
          next.ip,
          next.asn,
          next.countryCode,
          JSON.stringify(next.record),
          next.firstSeen,
          next.lastSeen || 0,
          next.expiresAt,
          now
        );
        accepted.push(next.ip);
      }
      if (accepted.length) this.bumpCorpusEpoch();
    });
    if (accepted.length) this.scheduleRetentionAlarm();
    return json({ ok: rejected.length === 0, accepted: accepted.length, rejected });
  }

  retireHosts(body) {
    const ips = [...new Set((Array.isArray(body.ips) ? body.ips : [body.ip])
      .map(canonicalizeIp)
      .filter(Boolean))].slice(0, 200);
    if (!ips.length) return json({ ok: false, error: "ips_required" }, 400);
    const now = Number.isFinite(body.now) ? Math.floor(body.now) : Date.now();
    const reason = boundedText(body.reason, 64, /^[a-z0-9_-]+$/i) || "final_probe_no_answer";
    const results = [];
    let changed = false;
    this.ctx.storage.transactionSync(() => {
      for (const ip of ips) {
        const host = one(this.sql.exec(
          "SELECT last_seen_at FROM hosts WHERE ip = ?",
          ip
        ));
        if (!host) {
          results.push({ ip, deleted: false, reason: "not_found" });
          continue;
        }
        const attempt = one(this.sql.exec(
          `SELECT last_attempt_at, lease_state, outcome FROM attempts
           WHERE ip = ? AND purpose = 'active_discovery'`,
          ip
        ));
        const observedAt = Number(host.last_seen_at) || 0;
        const evidenceOk = attempt && attempt.lease_state === "complete" &&
          Number(attempt.last_attempt_at) >= observedAt &&
          new Set(["not_observed", "target_error"]).has(attempt.outcome);
        if (!evidenceOk) {
          results.push({ ip, deleted: false, reason: "verified_retirement_evidence_required" });
          continue;
        }
        this.sql.exec("DELETE FROM hosts WHERE ip = ?", ip);
        this.setMeta(`retirement_receipt:${ip}:${now}`, JSON.stringify({
          ip,
          reason,
          outcome: attempt.outcome,
          last_attempt_at: new Date(Number(attempt.last_attempt_at)).toISOString(),
          retired_at: new Date(now).toISOString(),
        }));
        results.push({ ip, deleted: true, reason, outcome: attempt.outcome });
        changed = true;
      }
      if (changed) this.bumpCorpusEpoch();
    });
    return json({
      ok: results.every((row) => row.deleted || row.reason === "not_found"),
      retired: results.filter((row) => row.deleted).length,
      results,
    });
  }

  importAttempts(body) {
    const attempts = Array.isArray(body.attempts) ? body.attempts.slice(0, MAX_PAGE) : [];
    if (!attempts.length) return json({ ok: false, error: "attempts_required" }, 400);
    let imported = 0;
    let rejected = 0;
    for (const input of attempts) {
      const ip = canonicalizeIp(input?.ip);
      const at = parseTime(input?.last_attempt_at ?? input?.at, null);
      if (!ip || isPrivateOrLocal(ip) || !Number.isFinite(at)) {
        rejected++;
        continue;
      }
      const asn = normalizeAsn(input.asn);
      if (isExcluded(this.activeExclusions(), { ip, asn })) {
        rejected++;
        continue;
      }
      this.sql.exec(
        `INSERT INTO attempts(ip, purpose, asn, net_bucket, lease_id, lease_state,
           last_attempt_at, next_eligible_at, provenance_json, outcome, updated_at)
         VALUES (?, 'active_discovery', ?, ?, ?, 'complete', ?, ?, ?, 'legacy_import', ?)
         ON CONFLICT(ip, purpose) DO UPDATE SET
           asn = excluded.asn,
           net_bucket = excluded.net_bucket,
           lease_id = excluded.lease_id,
           lease_state = excluded.lease_state,
           last_attempt_at = excluded.last_attempt_at,
           next_eligible_at = excluded.next_eligible_at,
           provenance_json = excluded.provenance_json,
           outcome = excluded.outcome,
           updated_at = excluded.updated_at
         WHERE attempts.last_attempt_at < excluded.last_attempt_at`,
        ip,
        asn,
        addressBucket(ip),
        `legacy:${ip}`,
        at,
        at + ACTIVE_COOLDOWN_MS,
        JSON.stringify(input.provenance || { kind: "legacy_migration" }),
        at
      );
      imported++;
    }
    return json({ ok: rejected === 0, imported, rejected });
  }

  migrationStatus() {
    return json({
      ok: true,
      host_cursor: this.meta("migration_host_cursor") || null,
      attempt_cursor: this.meta("migration_attempt_cursor") || null,
      hosts_complete: this.meta("migration_hosts_complete") === "true",
      attempts_complete: this.meta("migration_attempts_complete") === "true",
      imported_hosts: Number(this.meta("migration_imported_hosts") || 0),
      imported_attempts: Number(this.meta("migration_imported_attempts") || 0),
      complete: this.meta("migration_complete") === "true",
    });
  }

  migrationCheckpoint(body) {
    if (body.host_cursor != null) this.setMeta("migration_host_cursor", body.host_cursor);
    if (body.attempt_cursor != null) this.setMeta("migration_attempt_cursor", body.attempt_cursor);
    if (body.hosts_complete === true) this.setMeta("migration_hosts_complete", "true");
    if (body.attempts_complete === true) this.setMeta("migration_attempts_complete", "true");
    // Derive the checkpoint counts from the authoritative tables. Retrying a
    // page after a Worker interruption may repeat idempotent upserts; summing
    // per-request "accepted" counts would inflate the expected total and make
    // an otherwise complete migration impossible to verify.
    this.setMeta(
      "migration_imported_hosts",
      Number(one(this.sql.exec("SELECT COUNT(*) AS n FROM hosts"))?.n || 0)
    );
    this.setMeta(
      "migration_imported_attempts",
      Number(one(this.sql.exec("SELECT COUNT(*) AS n FROM attempts"))?.n || 0)
    );
    return this.migrationStatus();
  }

  completeMigration(body) {
    const hostsComplete = this.meta("migration_hosts_complete") === "true";
    const attemptsComplete = this.meta("migration_attempts_complete") === "true";
    const hosts = Number(one(this.sql.exec("SELECT COUNT(*) AS n FROM hosts"))?.n || 0);
    const attempts = Number(one(this.sql.exec("SELECT COUNT(*) AS n FROM attempts"))?.n || 0);
    const pendingPurges = Number(one(this.sql.exec(
      "SELECT COUNT(*) AS n FROM purge_jobs WHERE status != 'complete'"
    ))?.n || 0);
    const generation = this.meta("current_aggregate_generation");
    const expectedHosts = Number(body.expected_hosts);
    const expectedAttempts = Number(body.expected_attempts);
    const verified = hostsComplete && attemptsComplete &&
      Number.isInteger(expectedHosts) && expectedHosts === hosts &&
      Number.isInteger(expectedAttempts) && expectedAttempts === attempts &&
      pendingPurges === 0 && !!generation;
    if (!verified) {
      return json({
        ok: false,
        error: "migration_verification_failed",
        hosts,
        attempts,
        expected_hosts: expectedHosts,
        expected_attempts: expectedAttempts,
        pending_purges: pendingPurges,
        aggregate_generation: generation || null,
      }, 409);
    }
    this.setMeta("migration_complete", "true");
    this.setMeta("migration_completed_at", Date.now());
    return json({ ok: true, hosts, attempts, aggregate_generation: generation });
  }

  purgeStatus(id) {
    const job = id ? one(this.sql.exec("SELECT * FROM purge_jobs WHERE id = ?", id)) : null;
    if (!job) return json({ ok: false, error: "purge_job_not_found" }, 404);
    const receipt = this.meta(`purge_receipt:${id}`);
    return json({
      ok: true,
      job: {
        id: job.id,
        type: job.rule_type,
        value: job.rule_value,
        status: job.status,
        matched: Number(job.matched),
        deleted: Number(job.deleted),
        created_at: new Date(Number(job.created_at)).toISOString(),
        completed_at: job.completed_at ? new Date(Number(job.completed_at)).toISOString() : null,
      },
      receipt: receipt ? JSON.parse(receipt) : null,
    });
  }

  resumePurge(body) {
    const id = String(body.id || "");
    const limit = Math.max(1, Math.min(Number(body.limit) || 200, MAX_PAGE));
    const job = one(this.sql.exec("SELECT * FROM purge_jobs WHERE id = ?", id));
    if (!job) return json({ ok: false, error: "purge_job_not_found" }, 404);
    if (job.status === "complete") return this.purgeStatus(id);

    let status = job.status;
    let hostCursor = job.host_cursor || "";
    let attemptCursor = job.attempt_cursor || "";
    let matched = Number(job.matched || 0);
    let deleted = Number(job.deleted || 0);
    let changed = false;

    if (status === "hosts" || status === "verify_hosts") {
      const page = rows(this.sql.exec(
        "SELECT ip, asn FROM hosts WHERE ip > ? ORDER BY ip LIMIT ?",
        hostCursor,
        limit
      ));
      const hits = page.filter((row) => ruleMatches(job.rule_type, job.rule_value, row));
      matched += hits.length;
      if (status === "verify_hosts" && hits.length) {
        status = "hosts";
        hostCursor = "";
      } else {
        for (const row of hits) {
          this.sql.exec("DELETE FROM hosts WHERE ip = ?", row.ip);
          deleted++;
          changed = true;
        }
        hostCursor = page.at(-1)?.ip || hostCursor;
        if (page.length < limit) {
          status = status === "hosts" ? "attempts" : "verify_attempts";
          if (status === "attempts") attemptCursor = "";
        }
      }
    } else if (status === "attempts" || status === "verify_attempts") {
      const [cursorIp, cursorPurpose] = decodeAttemptCursor(attemptCursor);
      const page = rows(this.sql.exec(
        `SELECT ip, purpose, asn FROM attempts
         WHERE ip > ? OR (ip = ? AND purpose > ?)
         ORDER BY ip, purpose LIMIT ?`,
        cursorIp,
        cursorIp,
        cursorPurpose,
        limit
      ));
      const hits = page.filter((row) => ruleMatches(job.rule_type, job.rule_value, row));
      matched += hits.length;
      if (status === "verify_attempts" && hits.length) {
        status = "attempts";
        attemptCursor = "";
      } else {
        for (const row of hits) {
          this.sql.exec("DELETE FROM attempts WHERE ip = ? AND purpose = ?", row.ip, row.purpose);
          deleted++;
        }
        attemptCursor = encodeAttemptCursor(page.at(-1)) || attemptCursor;
        if (page.length < limit) {
          if (status === "attempts") {
            status = "verify_hosts";
            hostCursor = "";
          } else {
            status = "complete";
          }
        }
      }
    }

    const now = Date.now();
    if (changed) this.bumpCorpusEpoch();
    this.sql.exec(
      `UPDATE purge_jobs SET status = ?, host_cursor = ?, attempt_cursor = ?,
       verification_pass = ?, matched = ?, deleted = ?, updated_at = ?, completed_at = ?
       WHERE id = ?`,
      status,
      hostCursor || null,
      attemptCursor || null,
      status.startsWith("verify_") || status === "complete" ? 1 : 0,
      matched,
      deleted,
      now,
      status === "complete" ? now : null,
      id
    );
    if (status === "complete") {
      this.setMeta(`purge_receipt:${id}`, JSON.stringify({
        id,
        rule_type: job.rule_type,
        rule_value: job.rule_value,
        verified_zero_matches: true,
        deleted,
        completed_at: new Date(now).toISOString(),
      }));
    }
    return this.purgeStatus(id);
  }

  runRetention(body = {}) {
    const now = Number.isFinite(body.now) ? Math.floor(body.now) : Date.now();
    const limit = Math.max(1, Math.min(Number(body.limit) || 200, MAX_PAGE));
    const due = rows(this.sql.exec(
      "SELECT ip FROM hosts WHERE expires_at <= ? ORDER BY expires_at, ip LIMIT ?",
      now,
      limit
    ));
    for (const row of due) this.sql.exec("DELETE FROM hosts WHERE ip = ?", row.ip);
    const attemptsCutoff = now - ATTEMPT_RETENTION_MS;
    this.sql.exec("DELETE FROM permits WHERE expires_at < ?", now);
    this.sql.exec("DELETE FROM rate_events WHERE at < ?", now - DAY_MS);
    this.sql.exec("DELETE FROM attempts WHERE updated_at < ?", attemptsCutoff);
    if (due.length) this.bumpCorpusEpoch();
    this.scheduleRetentionAlarm();
    const remaining = Number(one(this.sql.exec(
      "SELECT COUNT(*) AS n FROM hosts WHERE expires_at <= ?",
      now
    ))?.n || 0);
    return json({ ok: true, deleted: due.length, remaining, complete: remaining === 0 });
  }

  scheduleRetentionAlarm() {
    const next = Number(one(this.sql.exec(
      "SELECT MIN(expires_at) AS at FROM hosts"
    ))?.at || 0);
    if (next > 0 && this.ctx.storage?.setAlarm) {
      this.ctx.waitUntil(this.ctx.storage.setAlarm(Math.max(next, Date.now() + 1_000)));
    }
  }

  async alarm() {
    this.runRetention({ limit: MAX_PAGE });
  }

  runReconciliation(body = {}) {
    const limit = Math.max(1, Math.min(Number(body.limit) || 250, MAX_PAGE));
    let generation = one(this.sql.exec(
      "SELECT * FROM aggregate_generations WHERE status = 'building' ORDER BY started_at DESC LIMIT 1"
    ));
    const epoch = Number(this.meta("corpus_epoch") || 0);
    if (generation) {
      const startEpoch = Number(this.meta(`aggregate_epoch:${generation.id}`));
      if (startEpoch !== epoch) {
        this.sql.exec("UPDATE aggregate_generations SET status = 'aborted' WHERE id = ?", generation.id);
        this.sql.exec("DELETE FROM aggregate_counts WHERE generation_id = ?", generation.id);
        generation = null;
      }
    }
    if (!generation) {
      const id = crypto.randomUUID();
      const now = Date.now();
      this.sql.exec(
        "INSERT INTO aggregate_generations(id, status, cursor, started_at) VALUES (?, 'building', '', ?)",
        id,
        now
      );
      this.setMeta(`aggregate_epoch:${id}`, epoch);
      generation = { id, status: "building", cursor: "", started_at: now };
    }

    const page = rows(this.sql.exec(
      "SELECT ip, record_json FROM hosts WHERE ip > ? ORDER BY ip LIMIT ?",
      generation.cursor || "",
      limit
    ));
    for (const row of page) {
      const record = JSON.parse(row.record_json);
      // Passive index-only rows may be retained for migration bookkeeping, but
      // the public corpus/geo/stack figures explicitly mean "answered us".
      if (!record.last_seen) continue;
      const country = record.country_code || record.country || "ZZ";
      const asn = record.asn || UNKNOWN_ASN;
      const stacks = uniqStacks(record.stacks || [record.stack]);
      const buckets = [
        ["corpus", "reverified_hosts"],
        ["country", country],
        ["asn", asn],
        ...stacks.map((stack) => ["stack", stack]),
        ...stacks.map((stack) => ["country_stack", `${country}|${stack}`]),
      ];
      for (const [dimension, bucket] of buckets) {
        this.sql.exec(
          `INSERT INTO aggregate_counts(generation_id, dimension, bucket, count)
           VALUES (?, ?, ?, 1)
           ON CONFLICT(generation_id, dimension, bucket)
           DO UPDATE SET count = count + 1`,
          generation.id,
          dimension,
          bucket
        );
      }
    }
    const cursor = page.at(-1)?.ip || generation.cursor || "";
    this.sql.exec("UPDATE aggregate_generations SET cursor = ? WHERE id = ?", cursor, generation.id);
    const complete = page.length < limit;
    if (complete) {
      const finalEpoch = Number(this.meta("corpus_epoch") || 0);
      const startEpoch = Number(this.meta(`aggregate_epoch:${generation.id}`));
      if (finalEpoch !== startEpoch) {
        this.sql.exec("UPDATE aggregate_generations SET status = 'aborted' WHERE id = ?", generation.id);
        return json({ ok: true, complete: false, restarted: true, generation_id: generation.id });
      }
      const now = Date.now();
      this.ctx.storage.transactionSync(() => {
        this.sql.exec(
          "UPDATE aggregate_generations SET status = 'complete', completed_at = ? WHERE id = ?",
          now,
          generation.id
        );
        this.setMeta("current_aggregate_generation", generation.id);
      });
    }
    return json({
      ok: true,
      complete,
      generation_id: generation.id,
      scanned: page.length,
      cursor: complete ? null : cursor,
    });
  }

  currentAggregates() {
    const generation = this.meta("current_aggregate_generation");
    if (!generation) return json({ ok: false, error: "aggregate_generation_unavailable" }, 503);
    const counts = rows(this.sql.exec(
      `SELECT dimension, bucket, count FROM aggregate_counts
       WHERE generation_id = ? ORDER BY dimension, bucket`,
      generation
    ));
    const dimensions = {};
    for (const row of counts) {
      (dimensions[row.dimension] ||= {})[row.bucket] = Number(row.count);
    }
    const info = one(this.sql.exec(
      "SELECT completed_at FROM aggregate_generations WHERE id = ? AND status = 'complete'",
      generation
    ));
    return json({
      ok: true,
      generation_id: generation,
      completed_at: info?.completed_at ? new Date(Number(info.completed_at)).toISOString() : null,
      dimensions,
    });
  }

  checkRate(scope, key, limit, windowMs, now) {
    const count = Number(one(this.sql.exec(
      "SELECT COUNT(*) AS n FROM rate_events WHERE scope = ? AND bucket_key = ? AND at > ?",
      scope,
      key,
      now - windowMs
    ))?.n || 0);
    return count < limit;
  }

  acquireLease(body) {
    const now = Number.isFinite(body.now) ? Math.floor(body.now) : Date.now();
    const purpose = body.purpose;
    if (!new Set(["active_discovery", "hosted_self", "owned_canary"]).has(purpose)) {
      return json({ ok: false, error: "invalid_purpose" }, 400);
    }

    const ip = canonicalizeIp(body.ip);
    if (!ip || isPrivateOrLocal(ip)) {
      return json({ ok: false, error: "target_not_public_unicast" }, 400);
    }
    const asn = normalizeAsn(body.asn);
    const netBucket = addressBucket(ip);
    if (purpose === "owned_canary") {
      const configured = canonicalizeIp(this.env.OWNED_CANARY_TARGET_IP);
      const canaryHost = String(this.env.OWNED_CANARY_TARGET_HOST || "").trim().toLowerCase();
      if (
        this.env.CANARY_PROBE_ENABLED !== "true" ||
        !configured || ip !== configured || body.service !== "owned_canary" ||
        !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(canaryHost) ||
        canaryHost.includes("..")
      ) {
        return json({ ok: false, error: "owned_canary_not_authorized" }, 403);
      }
    } else if (body.service === "owned_canary") {
      return json({ ok: false, error: "owned_canary_profile_reserved" }, 403);
    }
    if (purpose === "active_discovery" && asn === UNKNOWN_ASN) {
      return json({ ok: false, error: "target_asn_required" }, 403);
    }
    if (
      purpose === "active_discovery" &&
      this.activeExclusions().some((entry) => entry.type === "asn")
    ) {
      // A source can omit or misattribute ASN metadata. Until an independent
      // BGP resolver is wired, an ASN-wide opt-out conservatively pauses all
      // third-party discovery rather than trusting the nominating index to
      // determine whether its own candidate is excluded.
      return json({ ok: false, error: "independent_asn_verification_required" }, 503);
    }
    if (purpose === "active_discovery" && !validProvenance(body.provenance, now, ip, asn)) {
      return json({ ok: false, error: "fresh_public_index_provenance_required" }, 403);
    }
    if (isExcluded(this.activeExclusions(), { ip, asn })) {
      return json({ ok: false, error: "target_excluded" }, 403);
    }

    const prior = one(this.sql.exec(
      "SELECT next_eligible_at FROM attempts WHERE ip = ? AND purpose = ?",
      ip,
      purpose
    ));
    if (purpose === "active_discovery" && prior && Number(prior.next_eligible_at) > now) {
      return json({
        ok: false,
        error: "probe_interval_active",
        next_eligible_at: new Date(Number(prior.next_eligible_at)).toISOString(),
      }, 409);
    }
    if (purpose === "hosted_self") {
      const live = one(this.sql.exec(
        `SELECT a.lease_id FROM attempts a
         JOIN permits p ON p.lease_id = a.lease_id
         WHERE a.ip = ? AND a.purpose = ?
           AND a.lease_state IN ('acquired', 'emitted')
           AND p.expires_at >= ? LIMIT 1`,
        ip,
        purpose,
        now
      ));
      if (live) return json({ ok: false, error: "probe_in_progress" }, 409);
    }

    const rateKeys = {
      hosted_ip_15m: ip,
      hosted_ip_day: ip,
      hosted_global_day: "global",
      active_unknown_asn: UNKNOWN_ASN,
      active_net: netBucket,
      active_asn: asn,
      active_global_minute: "global",
      owned_canary_10m: "global",
    };
    const policy = ratePolicy(purpose, asn);
    for (const [scope, limit, windowMs] of policy) {
      if (!this.checkRate(scope, rateKeys[scope], limit, windowMs, now)) {
        return json({ ok: false, error: "rate_limited", scope }, 429);
      }
    }

    const service = String(body.service || "").toLowerCase();
    const resolvedPort = resolvePort(service, body.port);
    if (!resolvedPort.ok) {
      return json({
        ok: false,
        error: resolvedPort.error,
        allowed_ports: resolvedPort.allowed,
      }, 400);
    }
    const port = resolvedPort.port;

    const leaseId = crypto.randomUUID();
    const permitId = crypto.randomUUID();
    const nextEligible = purpose === "active_discovery" ? now + ACTIVE_COOLDOWN_MS : now;
    this.ctx.storage.transactionSync(() => {
      for (const [scope] of policy) {
        this.sql.exec(
          "INSERT INTO rate_events(scope, bucket_key, at) VALUES (?, ?, ?)",
          scope,
          rateKeys[scope],
          now
        );
      }
      this.sql.exec(
        `INSERT INTO attempts(ip, purpose, asn, net_bucket, lease_id, lease_state,
          last_attempt_at, next_eligible_at, provenance_json, updated_at)
         VALUES (?, ?, ?, ?, ?, 'acquired', ?, ?, ?, ?)
         ON CONFLICT(ip, purpose) DO UPDATE SET
          asn = excluded.asn, net_bucket = excluded.net_bucket,
          lease_id = excluded.lease_id, lease_state = 'acquired',
          last_attempt_at = excluded.last_attempt_at,
          next_eligible_at = excluded.next_eligible_at,
          provenance_json = excluded.provenance_json, outcome = NULL,
          updated_at = excluded.updated_at`,
        ip,
        purpose,
        asn,
        netBucket,
        leaseId,
        now,
        nextEligible,
        JSON.stringify(body.provenance || null),
        now
      );
      this.sql.exec(
        `INSERT INTO permits(id, lease_id, ip, asn, service, port, purpose,
          remaining, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
        permitId,
        leaseId,
        ip,
        asn,
        service,
        port,
        purpose,
        now + PERMIT_TTL_MS,
        now
      );
    });

    return json({
      ok: true,
      lease_id: leaseId,
      permit_id: permitId,
      ip,
      asn,
      service,
      port,
      expires_at: new Date(now + PERMIT_TTL_MS).toISOString(),
      next_eligible_at: new Date(nextEligible).toISOString(),
    });
  }

  consumePermit(body) {
    const now = Number.isFinite(body.now) ? Math.floor(body.now) : Date.now();
    const permit = one(this.sql.exec(
      `SELECT p.*, a.provenance_json, a.lease_state FROM permits p
       LEFT JOIN attempts a ON a.lease_id = p.lease_id WHERE p.id = ?`,
      String(body.permit_id || "")
    ));
    if (!permit) return json({ ok: false, error: "permit_not_found" }, 404);
    if (Number(permit.expires_at) < now) {
      return json({ ok: false, error: "permit_expired" }, 410);
    }
    if (Number(permit.remaining) < 1) {
      return json({ ok: false, error: "permit_consumed" }, 409);
    }
    if (isExcluded(this.activeExclusions(), { ip: permit.ip, asn: permit.asn })) {
      return json({ ok: false, error: "target_excluded" }, 403);
    }
    if (permit.lease_state !== "acquired") {
      return json({ ok: false, error: "permit_invalidated" }, 409);
    }

    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        "UPDATE permits SET remaining = remaining - 1 WHERE id = ? AND remaining > 0",
        permit.id
      );
      this.sql.exec(
        "UPDATE attempts SET lease_state = 'emitted', updated_at = ? WHERE lease_id = ?",
        now,
        permit.lease_id
      );
    });
    return json({
      ok: true,
      lease_id: permit.lease_id,
      ip: permit.ip,
      asn: permit.asn,
      service: permit.service,
      port: permit.port,
      purpose: permit.purpose,
      provenance: permit.provenance_json ? JSON.parse(permit.provenance_json) : null,
      canary_hostname: permit.purpose === "owned_canary"
        ? String(this.env.OWNED_CANARY_TARGET_HOST || "").trim().toLowerCase()
        : null,
    });
  }

  completeLease(body) {
    const leaseId = String(body.lease_id || "");
    const allowed = new Set(["exposed", "not_observed", "target_error", "platform_error"]);
    if (!leaseId || !allowed.has(body.outcome)) {
      return json({ ok: false, error: "invalid_completion" }, 400);
    }
    const row = one(this.sql.exec(
      "SELECT lease_state FROM attempts WHERE lease_id = ?",
      leaseId
    ));
    if (!row) return json({ ok: false, error: "lease_not_found" }, 404);
    if (row.lease_state !== "emitted") {
      return json({ ok: false, error: "lease_not_emitted" }, 409);
    }
    this.sql.exec(
      "UPDATE attempts SET lease_state = 'complete', outcome = ?, updated_at = ? WHERE lease_id = ?",
      body.outcome,
      Date.now(),
      leaseId
    );
    return json({ ok: true, lease_id: leaseId, outcome: body.outcome });
  }
}
