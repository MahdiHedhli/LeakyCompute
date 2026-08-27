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

function validProvenance(provenance, now) {
  if (!provenance || provenance.kind !== "public_index") return false;
  if (!new Set(["shodan", "censys"]).has(provenance.source)) return false;
  const observed = Date.parse(provenance.observed_at || "");
  return Number.isFinite(observed) && observed <= now && now - observed <= PROVENANCE_MAX_AGE_MS;
}

function ratePolicy(purpose, asn) {
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
    `);
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method === "GET" && path === "/health") return this.health();
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
    return json({ error: "not_found" }, 404);
  }

  health() {
    const hosts = one(this.sql.exec("SELECT COUNT(*) AS n FROM hosts"))?.n || 0;
    const attempts = one(this.sql.exec("SELECT COUNT(*) AS n FROM attempts"))?.n || 0;
    const exclusions = one(
      this.sql.exec("SELECT COUNT(*) AS n FROM exclusions WHERE active = 1")
    )?.n || 0;
    return json({ ok: true, schema: 1, hosts, attempts, exclusions });
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
    }
    return json({
      ok: rejected.length === 0,
      accepted,
      rejected,
      total: this.activeExclusions().length,
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
    if (!new Set(["active_discovery", "hosted_self"]).has(purpose)) {
      return json({ ok: false, error: "invalid_purpose" }, 400);
    }

    const ip = canonicalizeIp(body.ip);
    if (!ip || isPrivateOrLocal(ip)) {
      return json({ ok: false, error: "target_not_public_unicast" }, 400);
    }
    const asn = normalizeAsn(body.asn);
    const netBucket = addressBucket(ip);
    if (purpose === "active_discovery" && !validProvenance(body.provenance, now)) {
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

    const rateKeys = {
      hosted_ip_15m: ip,
      hosted_ip_day: ip,
      hosted_global_day: "global",
      active_unknown_asn: UNKNOWN_ASN,
      active_net: netBucket,
      active_asn: asn,
      active_global_minute: "global",
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
    const permit = one(
      this.sql.exec("SELECT * FROM permits WHERE id = ?", String(body.permit_id || ""))
    );
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
    this.sql.exec(
      "UPDATE attempts SET lease_state = 'complete', outcome = ?, updated_at = ? WHERE lease_id = ?",
      body.outcome,
      Date.now(),
      leaseId
    );
    return json({ ok: true, lease_id: leaseId, outcome: body.outcome });
  }
}
