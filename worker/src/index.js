/**
 * LeakyCompute API Worker
 * Public:  GET /v1/health, GET /v1/stats, POST /v1/check
 * Lab:     GET /v1/research/me, GET /v1/research/catalog
 * Admin:   POST /v1/admin/allowlist  (GitHub Action sync token)
 *
 * Safe probes only. No mass scan. No exploit payloads.
 */
import { json, noContent } from "./lib/cors.js";
import { consume, intEnv } from "./lib/ratelimit.js";
import { logAbuse } from "./lib/abuse.js";
import { validateTarget, isPrivateOrLocal } from "./lib/check.js";
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
} from "./lib/discovery.js";

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

      if (path === "/v1/admin/allowlist" && request.method === "POST") {
        return handleAdminAllowlist(request, env);
      }

      if (path === "/v1/admin/discovery/hits" && request.method === "GET") {
        return handleDiscoveryHits(request, env);
      }

      if (path === "/v1/admin/discovery/ingest" && request.method === "POST") {
        return handleDiscoveryIngest(request, env);
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
};

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

  const results = run.results;
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
      hits: hits.map((h) => ({
        ip: h.ip,
        port: h.port,
        last_seen: h.last_seen,
        first_seen: h.first_seen,
        times_seen: h.times_seen,
        models: h.models,
        source: h.source,
        stack: h.stack || null,
        country: h.country || null,
        country_code: h.country_code || null,
        city: h.city || null,
        asn: h.asn || null,
        org: h.org || null,
        product: h.product || null,
        vulns: h.vulns || [],
      })),
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
  if (!Array.isArray(results) || results.length === 0) {
    return json({ error: "results_required" }, 400, request, env);
  }
  // Keep batches small: KV write budget + Worker CPU on free tier
  if (results.length > 150) {
    return json({ error: "batch_too_large", max: 150 }, 400, request, env);
  }
  const summary = await ingestDiscoveryBatch(env, {
    results,
    run_meta: body.run_meta || null,
  });
  return json({ ok: true, ...summary }, 200, request, env);
}
