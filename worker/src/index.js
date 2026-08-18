/**
 * LeakyCompute API Worker
 * Public:  GET /v1/health, GET /v1/stats, POST /v1/check
 * Lab:     GET /v1/research/me, GET /v1/research/catalog,
 *          GET /v1/research/lab/{catalog,map,validation,host}
 * Admin:   POST /v1/admin/allowlist, /v1/admin/exclusions,
 *          /v1/admin/discovery/{ingest,sweep}; GET /v1/admin/exclusions,
 *          /v1/admin/discovery/hits
 * Cron:    I-26 retention sweep (see scheduled() and [triggers] in wrangler.toml)
 *
 * Raw addresses leave this Worker only through the Access-gated research lab
 * and the admin-token routes; every public route above returns aggregates
 * (I-14). Safe probes only. No mass scan. No exploit payloads.
 */
import { json, noContent } from "./lib/cors.js";
import { consume, intEnv } from "./lib/ratelimit.js";
import { logAbuse } from "./lib/abuse.js";
import { validateTarget, isPrivateOrLocal } from "./lib/check.js";
import { loadExclusions, isExcluded, addExclusions } from "./lib/exclusions.js";
import {
  runChecks,
  overallSeverity,
  SERVICES,
  TIER1,
} from "./lib/services.js";
import {
  getLiveStats,
  recordCheckResult,
  publicStatsPayload,
  getValidatedCatalog,
} from "./lib/stats.js";
import { resolveResearcher } from "./lib/access.js";
import {
  isAllowed,
  getAllowEntry,
  approveResearcher,
  revokeResearcher,
} from "./lib/allowlist.js";
import { verifyTurnstile } from "./lib/turnstile.js";
import {
  recordExposedHost,
  listHits,
  ingestDiscoveryBatch,
  sweepExpiredHosts,
  listExpiringHosts,
  retireUnreachableHost,
  getLaneCursors,
  setLaneCursor,
  FINAL_VERIFY_DAYS,
  purgeExcluded,
  getProbeAttempts,
  checkWriteBudget,
  RETENTION_DAYS,
} from "./lib/discovery.js";
import { enrichServicesWithOsv } from "./lib/osv.js";
import { routeLab } from "./lib/lab.js";

// Embedded compact snapshot meta (full catalog served from Pages/lab static seed)
const SNAPSHOT_NOTE =
  "Research snapshot is a filtered archive-era seed, not a live internet census. Live counts include voluntary checks and capped Shodan-seeded discovery re-probes.";

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return noContent(request, env);
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (path === "/" || path === "/v1/health") {
        return json(
          {
            service: "leakycompute-api",
            ok: true,
            environment: env.ENVIRONMENT || "unknown",
            time: new Date().toISOString(),
          },
          200,
          request,
          env
        );
      }

      if (path === "/v1/stats" && request.method === "GET") {
        return handleStats(request, env);
      }

      if (path === "/v1/check" && request.method === "POST") {
        return handleCheck(request, env, ctx);
      }

      if (path === "/v1/research/me" && request.method === "GET") {
        return handleResearchMe(request, env);
      }

      if (path === "/v1/research/catalog" && request.method === "GET") {
        return handleResearchCatalog(request, env);
      }

      // Researcher lab (/v1/research/lab/*). routeLab owns its own 404 and 405
      // for that prefix, so an unknown lab path cannot fall through to a route
      // gated differently. Each handler re-checks Access identity and the
      // researcher allowlist itself: these are the only routes besides the
      // admin token that emit raw addresses, and I-14 must not depend on this
      // router having mounted them correctly.
      const labResponse = await routeLab(request, env);
      if (labResponse) return labResponse;

      if (path === "/v1/admin/allowlist" && request.method === "POST") {
        return handleAdminAllowlist(request, env);
      }

      if (path === "/v1/admin/exclusions" && request.method === "POST") {
        return handleAdminExclusions(request, env);
      }

      if (path === "/v1/admin/exclusions" && request.method === "GET") {
        return handleListExclusions(request, env);
      }

      if (path === "/v1/admin/discovery/hits" && request.method === "GET") {
        return handleDiscoveryHits(request, env);
      }

      if (path === "/v1/admin/discovery/clock" && request.method === "GET") {
        return handleDiscoveryClock(request, env);
      }

      if (path === "/v1/admin/discovery/ingest" && request.method === "POST") {
        return handleDiscoveryIngest(request, env);
      }

      if (path === "/v1/admin/discovery/sweep" && request.method === "POST") {
        return handleDiscoverySweep(request, env);
      }

      if (path === "/v1/admin/discovery/expiring" && request.method === "GET") {
        return handleExpiring(request, env);
      }

      if (path === "/v1/admin/discovery/retire" && request.method === "POST") {
        return handleRetire(request, env);
      }

      if (path === "/v1/admin/discovery/cursors" && request.method === "GET") {
        return handleGetCursors(request, env);
      }

      if (path === "/v1/admin/discovery/cursors" && request.method === "POST") {
        return handleSetCursor(request, env);
      }

      return json({ error: "not_found" }, 404, request, env);
    } catch (err) {
      return json(
        { error: "internal_error", message: String(err?.message || err) },
        500,
        request,
        env
      );
    }
  },

  /**
   * I-26 expiry on silence. The retention rule is only real if something runs
   * it unattended: the admin route exists for a maintainer who wants it now,
   * the cron is what makes 180 days a deletion rather than an intention.
   */
  async scheduled(event, env, ctx) {
    // The sweep is bounded per invocation (KV operations count against the
    // Worker's subrequest ceiling) and resumes from a stored cursor, so a
    // corpus larger than one window is walked over successive nights rather
    // than throwing into an unhandled waitUntil rejection every time.
    ctx.waitUntil(
      sweepExpiredHosts(env, { retentionDays: retentionWindow(env) })
        .then((s) => {
          if (!s.complete) {
            console.log(`retention sweep partial: ${s.deleted} deleted, ${s.remaining} to go`);
          }
        })
        // A retention sweep that fails silently is indistinguishable from one
        // that found nothing due — which is the wrong thing to believe about
        // I-26. Nothing else can surface this, so it goes to the log.
        .catch((err) => console.error("retention sweep failed:", err?.message || err))
    );
  },
};

/**
 * I-26 fixes the ceiling at 180 days from the last successful probe. A
 * deployment may hold records for less time, never for more, so both the env
 * var and the admin request body can only tighten the window — widening it
 * would be an amendment to the invariant, not a configuration change.
 */
function retentionWindow(env, requested) {
  const configured = intEnv(env, "CORPUS_EXPIRY_DAYS", RETENTION_DAYS);
  const asked = Number.isFinite(requested) && requested > 0 ? requested : configured;
  return Math.max(1, Math.min(asked, configured, RETENTION_DAYS));
}

async function handleStats(request, env) {
  const live = await getLiveStats(env);
  const payload = await publicStatsPayload(env, live);
  payload.methodology = SNAPSHOT_NOTE;
  return json(payload, 200, request, env, {
    "Cache-Control": "public, max-age=30",
  });
}

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "0.0.0.0"
  );
}

async function handleCheck(request, env, ctx) {
  const ip = clientIp(request);
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const turnstile = await verifyTurnstile(env, body.turnstile_token, ip);
  if (!turnstile.ok) {
    await logAbuse(env, {
      action: "check",
      result: "turnstile_fail",
      clientIp: ip,
      reason: "turnstile",
    });
    return json({ error: "turnstile_failed" }, 403, request, env);
  }

  const timeoutMs = intEnv(env, "CHECK_TIMEOUT_MS", 3000);

  const override = !!(body.target && String(body.target).trim());
  const authorized = !!body.authorized;

  let targetHost = ip;
  let mode = "own_ip";

  if (override) {
    if (!authorized) {
      await logAbuse(env, {
        action: "check",
        result: "override_denied",
        clientIp: ip,
        target: body.target,
        reason: "missing_authorization",
        override: true,
      });
      return json(
        {
          error: "authorization_required",
          message:
            "Override checks require authorized=true confirming you own or may test the target.",
        },
        400,
        request,
        env
      );
    }
    const vt = validateTarget(body.target);
    if (!vt.ok) {
      return json({ error: vt.error }, 400, request, env);
    }
    // Public override: reject obvious private targets (use CLI locally for LAN)
    if (isPrivateOrLocal(vt.host)) {
      return json(
        {
          error: "private_target_not_allowed",
          message:
            "Private/reserved addresses cannot be probed from the public API. Use the local CLI for lab networks.",
        },
        400,
        request,
        env
      );
    }
    targetHost = vt.host;
    mode = "override";
  }

  // I-25: an operator who asked to be left alone is honoured before any request
  // is emitted, in both modes. The exclusion is the network owner's instruction
  // and it outranks a visitor on that network asking us to probe it — same
  // precedence rule as exclusion-beats-scan-request. ASN matching applies only
  // where we know the ASN (own_ip, via Cloudflare); an override target is
  // matched on address alone.
  const exclusions = await loadExclusions(env);
  if (
    isExcluded(exclusions, {
      ip: targetHost,
      asn: mode === "own_ip" ? request.cf?.asn : null,
    })
  ) {
    await logAbuse(env, {
      action: "check",
      result: "excluded",
      clientIp: ip,
      target: targetHost,
      reason: "exclusion_list",
      override,
    });
    return json(
      {
        error: "target_excluded",
        message:
          "This address space is on the scanning exclusion list at the network " +
          "owner's request, so we will not probe it. If you own this space and " +
          "want the exclusion withdrawn, say so on the removal issue that created it.",
      },
      403,
      request,
      env
    );
  }

  // Which tier-1 services to check. Default: all of them.
  let services = TIER1;
  if (Array.isArray(body.services) && body.services.length) {
    services = body.services
      .map((s) => String(s).toLowerCase().trim())
      .filter((s) => SERVICES[s]);
    if (!services.length) {
      return json(
        { error: "unknown_service", supported: TIER1 },
        400,
        request,
        env
      );
    }
  }

  // Per-service port overrides, validated against each service's known ports.
  // Legacy clients send a bare `port` — treat it as the Ollama port.
  const ports = {};
  if (body.ports && typeof body.ports === "object") {
    for (const [k, v] of Object.entries(body.ports)) {
      if (SERVICES[k]) ports[k] = v;
    }
  }
  if (body.port != null && body.port !== "" && ports.ollama == null) {
    ports.ollama = body.port;
  }

  // Rate limits
  const ownWin = intEnv(env, "RL_OWN_WINDOW_SEC", 900);
  const ownMax = intEnv(env, "RL_OWN_MAX", 5);
  const ownDay = intEnv(env, "RL_OWN_DAY_MAX", 20);
  const ovWin = intEnv(env, "RL_OVERRIDE_WINDOW_SEC", 900);
  const ovMax = intEnv(env, "RL_OVERRIDE_MAX", 2);
  const ovDay = intEnv(env, "RL_OVERRIDE_DAY_MAX", 5);
  const gDay = intEnv(env, "RL_GLOBAL_DAY_MAX", 2000);

  const global = await consume(env, "global:check", gDay, 86400);
  if (!global.ok) {
    await logAbuse(env, {
      action: "check",
      result: "rate_limited_global",
      clientIp: ip,
      override,
    });
    return json({ error: "rate_limited", scope: "global", reset: global.reset }, 429, request, env);
  }

  if (mode === "own_ip") {
    const w = await consume(env, `own:${ip}`, ownMax, ownWin);
    const d = await consume(env, `own_day:${ip}`, ownDay, 86400);
    if (!w.ok || !d.ok) {
      await logAbuse(env, {
        action: "check",
        result: "rate_limited_own",
        clientIp: ip,
      });
      return json(
        { error: "rate_limited", scope: "own_ip", reset: (!w.ok ? w.reset : d.reset) },
        429,
        request,
        env
      );
    }
  } else {
    const w = await consume(env, `ov:${ip}`, ovMax, ovWin);
    const d = await consume(env, `ov_day:${ip}`, ovDay, 86400);
    if (!w.ok || !d.ok) {
      await logAbuse(env, {
        action: "check",
        result: "rate_limited_override",
        clientIp: ip,
        target: targetHost,
        override: true,
      });
      return json(
        { error: "rate_limited", scope: "override", reset: (!w.ok ? w.reset : d.reset) },
        429,
        request,
        env
      );
    }
  }

  const run = await runChecks(targetHost, { services, ports, timeoutMs });
  if (!run.ok) {
    return json(
      {
        error: run.error,
        service: run.service,
        allowed_ports: run.allowed,
        message:
          "Only the known AI service ports are accepted. This checker is not a general-purpose port prober.",
      },
      400,
      request,
      env
    );
  }

  // Tier-2: attach OSV.dev vulns when we have a confirmed version string.
  // enrichServicesWithOsv also merges top hits into svc.findings, so
  // overallSeverity() already reflects version-aware CVE/GHSA severity.
  const results = await enrichServicesWithOsv(run.results, env);
  const anyExposed = results.some((r) => r.exposed);
  const severity = overallSeverity(results);
  const ollama = results.find((r) => r.service === "ollama");

  // Record aggregates + private hit list (for discovery neighborhood expansion)
  const tasks = [
    recordCheckResult(env, {
      exposed: anyExposed,
      models: ollama?.models || [],
      services: results.map((r) => ({
        service: r.service,
        detected: r.detected,
        exposed: r.exposed,
      })),
    }),
    logAbuse(env, {
      action: "check",
      result: anyExposed ? "exposed" : "not_exposed",
      clientIp: ip,
      target: mode === "override" ? targetHost : null,
      override: mode === "override",
      meta: {
        mode,
        severity,
        services: results.map((r) => ({
          s: r.service,
          port: r.port,
          detected: r.detected,
          exposed: r.exposed,
          status: r.status,
          latency_ms: r.latency_ms,
        })),
      },
    }),
  ];
  // One record per host, not per service: the hit store is keyed by IP, so
  // parallel writes for the same host would read the same `prev` and clobber
  // each other. Collapse every exposed service into a single write.
  const exposedServices = results.filter((r) => r.exposed);
  if (exposedServices.length) {
    // Store the probed host (client IP for own mode, target for override)
    tasks.push(
      recordExposedHost(env, {
        ip: targetHost,
        port: exposedServices[0].port,
        ports: exposedServices.map((r) => r.port),
        stack: exposedServices[0].service,
        stacks: exposedServices.map((r) => r.service),
        models: exposedServices.flatMap((r) => r.models || []),
        source: mode === "override" ? "public_override" : "public_self_check",
      })
    );
  }
  ctx.waitUntil(Promise.all(tasks));

  return json(
    {
      ok: true,
      mode,
      // Never echo full client IP for own mode beyond confirmation
      target: mode === "override" ? targetHost : "your_egress_ip",
      checked_at: new Date().toISOString(),
      overall_severity: severity,
      any_exposed: anyExposed,
      services: results,
      guidance: anyExposed
        ? "At least one AI service answered an unauthenticated read from the public internet. Work through the per-service remediation below."
        : "No unauthenticated AI service responded from our vantage point.",
      limitations:
        "A clean result is not proof of safety. Probes originate from Cloudflare's network and cover only " +
        "the listed services on their known ports, so a filtered, rate-limited, or geo-blocked host looks " +
        "identical to one that is not running the service — and anything bound to another port, or reachable " +
        "only from inside your network, is out of scope.",

      // --- legacy fields (pre-tier-1 clients read these) ---------------
      port: ollama?.port ?? SERVICES.ollama.defaultPort,
      exposed: !!ollama?.exposed,
      auth_required: !!ollama?.authenticated,
      latency_ms: ollama?.latency_ms ?? null,
      models: ollama?.exposed ? ollama.models || [] : [],
      error: ollama?.error || null,
    },
    200,
    request,
    env
  );
}

async function handleResearchMe(request, env) {
  const identity = await resolveResearcher(request, env);
  if (!identity) {
    return json(
      {
        authenticated: false,
        allowed: false,
        message:
          "Sign in via Cloudflare Access (GitHub). Cross-origin lab calls must send Cf-Access-Jwt-Assertion when configured.",
      },
      401,
      request,
      env
    );
  }
  const allowed = await isAllowed(env, identity.login);
  const entry = allowed ? await getAllowEntry(env, identity.login) : null;
  return json(
    {
      authenticated: true,
      allowed,
      login: identity.login,
      email: identity.email,
      dev: !!identity.dev,
      entry,
      message: allowed
        ? "Welcome, researcher."
        : "GitHub identity recognized but not allowlisted. Open a research access issue and wait for approval.",
    },
    allowed ? 200 : 403,
    request,
    env
  );
}

async function handleResearchCatalog(request, env) {
  const identity = await resolveResearcher(request, env);
  if (!identity) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  if (!(await isAllowed(env, identity.login))) {
    return json({ error: "forbidden", login: identity.login }, 403, request, env);
  }

  // Validated catalog from KV if present; else empty (lab UI loads static seed client-side)
  const validated = await getValidatedCatalog(env);
  const live = await getLiveStats(env);
  return json(
    {
      login: identity.login,
      research_snapshot: {
        models: parseInt(env.SNAPSHOT_MODELS || "0", 10) || 0,
        hosts: parseInt(env.SNAPSHOT_HOSTS || "0", 10) || 0,
      },
      validated,
      live_instrumented: {
        exposed_total: live.exposed_total || 0,
        checks_total: live.checks_total || 0,
        models_top: live.models_top || [],
      },
      chat_enabled: false,
      note: "Launch mode: catalog + stats only. Lab chat ships after Access lockdown.",
    },
    200,
    request,
    env
  );
}

function requireAdmin(request, env) {
  const token = request.headers.get("X-Admin-Token") || "";
  const expected = env.ADMIN_SYNC_TOKEN || "";
  return !!(expected && token && token === expected);
}

async function handleAdminAllowlist(request, env) {
  if (!requireAdmin(request, env)) {
    await logAbuse(env, {
      action: "admin_allowlist",
      result: "unauthorized",
      clientIp: clientIp(request),
      reason: "bad_token",
    });
    return json({ error: "unauthorized" }, 401, request, env);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400, request, env);
  }

  const op = body.op || "approve";
  const login = body.login;
  if (!login) return json({ error: "login_required" }, 400, request, env);

  if (op === "revoke") {
    const entry = await revokeResearcher(env, login);
    return json({ ok: true, entry }, 200, request, env);
  }

  const entry = await approveResearcher(env, {
    login,
    issue: body.issue_number,
    approved_by: body.approved_by,
    meta: body.meta || null,
  });
  return json({ ok: true, entry }, 200, request, env);
}

/**
 * Add exclusions (I-25). Called by the removal-request Action on issue open —
 * honoured on receipt, reviewed afterwards. Adding is the only write path:
 * withdrawing an exclusion is deliberate manual work, so a replayed or
 * duplicated request can only ever widen the list.
 */
async function handleAdminExclusions(request, env) {
  if (!requireAdmin(request, env)) {
    await logAbuse(env, {
      action: "admin_exclusions",
      result: "unauthorized",
      clientIp: clientIp(request),
      reason: "bad_token",
    });
    return json({ error: "unauthorized" }, 401, request, env);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400, request, env);
  }

  const lines = Array.isArray(body.entries)
    ? body.entries
    : String(body.scope || "").split(/[\r\n,]+/);

  const result = await addExclusions(env, lines, {
    issue_number: body.issue_number ?? null,
    source: body.source || "removal-request",
    // Only a maintainer label can auto-honour space broader than the bound.
    allowBroad: !!body.allow_broad,
  });

  const purged = await purgeExcludedRecords(env);

  // Rejected lines are reported, never silently dropped: an operator who
  // fat-fingers a CIDR must find out, not assume they are excluded.
  return json({ ok: true, ...result, purged }, 200, request, env);
}

/**
 * I-25: "exclusion deletes existing records as well as stopping future probes."
 * An operator who asks to be left alone has not asked us to keep what we
 * already hold about them.
 *
 * Deliberately best-effort: if the corpus cannot be deleted from, the exclusion
 * is still recorded and the failure is reported in the response. Refusing the
 * whole removal request in that case would leave the operator with neither the
 * deletion nor the opt-out, which is strictly worse for them.
 *
 * Runs over the *whole* stored list, not the lines this request happened to
 * add. addExclusions drops entries it already holds, so an operator whose first
 * removal request hit a KV error and who re-filed a week later got an empty
 * `accepted` list and no purge at all — the deletion half of I-25 held only for
 * a first submission that happened to succeed. Re-filing now retries it, and so
 * does any later exclusion write.
 */
async function purgeExcludedRecords(env) {
  if (!env.KV || typeof env.KV.delete !== "function") {
    return { deleted: 0, matched: 0, error: "kv_delete_unavailable" };
  }
  try {
    const entries = await loadExclusions(env);
    // Counts only in the response body: this endpoint is admin-gated, but the
    // list of addresses we just deleted is not something to hand back (I-14).
    return await purgeExcluded(env, entries);
  } catch (err) {
    return { deleted: 0, matched: 0, error: String(err?.message || err) };
  }
}

/** The discovery runner fetches this before probing and refuses to run without it. */
async function handleListExclusions(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const entries = await loadExclusions(env);
  return json({ ok: true, count: entries.length, entries }, 200, request, env);
}

/**
 * Hosts due a final probe before retention deletes them (I-26 + spec §4).
 * The runner treats these as its highest-priority candidates; they still pass
 * every gate, so a host whose provenance was only ever a self-check is dropped
 * here exactly as it would be anywhere else.
 */
async function handleExpiring(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const url = new URL(request.url);
  const asked = Number(url.searchParams.get("days"));
  // Only ever earlier than the default: asking for a longer fuse would let a
  // caller quietly opt records out of their final verification.
  const dueDays = Number.isFinite(asked) && asked > 0
    ? Math.min(asked, FINAL_VERIFY_DAYS)
    : FINAL_VERIFY_DAYS;
  const limit = Math.min(Number(url.searchParams.get("limit")) || 500, 1000);
  const res = await listExpiringHosts(env, { dueDays, limit });
  return json({ ok: true, due_days: dueDays, ...res }, 200, request, env);
}

/** Deletion with evidence: the final probe ran and found nothing. */
async function handleRetire(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400, request, env);
  }
  const ips = Array.isArray(body.ips) ? body.ips : [body.ip].filter(Boolean);
  if (!ips.length) return json({ error: "ips_required" }, 400, request, env);
  const results = [];
  for (const ip of ips.slice(0, 200)) {
    results.push(await retireUnreachableHost(env, String(ip), { reason: body.reason }));
  }
  return json({ ok: true, retired: results.filter((r) => r.deleted).length, results }, 200, request, env);
}

async function handleGetCursors(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  return json({ ok: true, cursors: await getLaneCursors(env) }, 200, request, env);
}

async function handleSetCursor(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400, request, env);
  }
  const updates = Array.isArray(body.cursors) ? body.cursors : [body];
  const out = [];
  for (const u of updates.slice(0, 100)) {
    if (!u || !u.lane) continue;
    out.push(await setLaneCursor(env, String(u.lane), {
      page: u.page,
      exhausted: u.exhausted,
      observed: u.observed,
    }));
  }
  return json({ ok: true, updated: out.filter(Boolean).length, cursors: out }, 200, request, env);
}

async function handleDiscoveryHits(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "500", 10) || 500, 2000);
  const sort = url.searchParams.get("sort") || "last_seen"; // last_seen | country | asn
  const hits = await listHits(env, { limit, sort });
  return json(
    {
      count: hits.length,
      sort,
      // Mirrors RETAINED_FIELDS in discovery.js. Model lists, city, org,
      // product banners, vulns and times_seen are no longer stored per host
      // (I-26), so serialising them here would only promise the runner and the
      // lab UI fields that are permanently null.
      hits: hits.map((h) => ({
        ip: h.ip,
        port: h.port,
        ports: h.ports || (h.port ? [h.port] : []),
        last_seen: h.last_seen,
        first_seen: h.first_seen,
        source: h.source,
        stack: h.stack || null,
        stacks: h.stacks || (h.stack ? [h.stack] : []),
        version: h.version || null,
        country: h.country || null,
        country_code: h.country_code || null,
        asn: h.asn || null,
      })),
    },
    200,
    request,
    env
  );
}

/**
 * I-24 re-probe clock: when we last *sent* each host a request.
 *
 * Separate from /hits because the two answer different questions. /hits is the
 * corpus — hosts that answered — and it is paged, so a host first seen months
 * ago falls outside the window and looks to the runner like one we have never
 * touched. This returns the whole ledger in one read, including the hosts that
 * did not answer and therefore have no record at all. Those are precisely the
 * operators who have already closed the port, and without this they were the
 * only ones the 14-day interval did not protect.
 *
 * Admin-gated like the hit store: it is a list of addresses (I-14).
 */
async function handleDiscoveryClock(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const attempts = await getProbeAttempts(env);
  return json(
    {
      ok: true,
      count: Object.keys(attempts).length,
      reprobe_interval_days: intEnv(env, "REPROBE_INTERVAL_DAYS", 14),
      attempts,
    },
    200,
    request,
    env
  );
}

async function handleDiscoveryIngest(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  // Free-tier guard: few discovery ingests per hour (active scan runs off-Worker)
  const rl = await consume(env, "admin:discovery_ingest", 10, 3600);
  if (!rl.ok) {
    return json(
      { error: "rate_limited", scope: "discovery_ingest", reset: rl.reset, limit: 10 },
      429,
      request,
      env
    );
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400, request, env);
  }
  const results = body.results || [];
  if (!Array.isArray(results)) {
    return json({ error: "results_required" }, 400, request, env);
  }
  // An empty batch is legitimate when the envelope still carries an observation.
  // A run whose candidates were all skipped by the I-24 interval probed nothing
  // yet still read what the index lists, and refusing it would make the public
  // passive count a function of whether we happened to be due a probe.
  const observedOnly =
    results.length === 0 &&
    (body.indexed_observed != null || body.run_meta?.indexed_observed != null);
  if (results.length === 0 && !observedOnly) {
    return json({ error: "results_required" }, 400, request, env);
  }
  // Keep batches small: KV write budget + Worker CPU on free tier
  if (results.length > 150) {
    return json({ error: "batch_too_large", max: 150 }, 400, request, env);
  }

  // Refuse before the first write rather than failing partway through. A batch
  // that stops mid-flight leaves records without the aggregates that describe
  // them, which is a worse outcome than not ingesting at all. Roughly one put
  // per host plus the fixed aggregate flush.
  const budget = await checkWriteBudget(env, results.length + 8);
  if (!budget.ok) {
    return json(
      {
        error: "kv_write_budget_exhausted",
        message:
          "Refusing to ingest: this batch would cross today's KV put ceiling, " +
          "and a partial write leaves the corpus disagreeing with the counts " +
          "that describe it. Retry after 00:00 UTC, send a smaller batch, or " +
          "raise KV_DAILY_PUT_BUDGET on a paid plan.",
        used: budget.used,
        budget: budget.budget,
        remaining: budget.remaining,
        estimated: budget.estimated,
      },
      429,
      request,
      env
    );
  }
  const summary = await ingestDiscoveryBatch(env, {
    results,
    run_meta: body.run_meta || null,
    // Spec §4's second number. Passive breadth is a property of the run, not of
    // any result row, so it arrives on the envelope; accepted at either level
    // because the runner reports it in run_meta.
    indexed_observed: body.indexed_observed ?? null,
  });
  return json({ ok: true, ...summary }, 200, request, env);
}

/**
 * Run the I-26 retention sweep on demand. Same work the cron does — this route
 * exists so a maintainer can force it after a policy change, and so the result
 * is inspectable rather than only visible in cron logs.
 *
 * POST because it deletes. I-1's GET-only rule governs requests we send to
 * third-party targets; this is our own store, and a sweep that deleted records
 * on a GET would be reachable by a prefetch.
 */
async function handleDiscoverySweep(request, env) {
  if (!requireAdmin(request, env)) {
    await logAbuse(env, {
      action: "admin_discovery_sweep",
      result: "unauthorized",
      clientIp: clientIp(request),
      reason: "bad_token",
    });
    return json({ error: "unauthorized" }, 401, request, env);
  }
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const days = retentionWindow(env, Number(body.retention_days));
  try {
    const summary = await sweepExpiredHosts(env, { retentionDays: days });
    // Counts and a cutoff timestamp only — never the addresses removed (I-14).
    return json({ ok: true, retention_days: days, ...summary }, 200, request, env);
  } catch (err) {
    if (String(err?.message) === "kv_delete_unavailable") {
      return json(
        {
          error: "kv_delete_unavailable",
          message:
            "The bound store cannot delete keys, so retention cannot be enforced. " +
            "Reporting success here would claim an I-26 deletion that did not happen.",
        },
        501,
        request,
        env
      );
    }
    throw err;
  }
}
