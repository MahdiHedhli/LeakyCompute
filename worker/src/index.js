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
import {
  validateTarget,
  validatePort,
  isPrivateOrLocal,
  probeOllama,
} from "./lib/check.js";
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

// Embedded compact snapshot meta (full catalog served from Pages/lab static seed)
const SNAPSHOT_NOTE =
  "Research snapshot is a filtered archive-era seed, not a live global scan.";

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
  const payload = publicStatsPayload(env, live);
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

  const defaultPort = intEnv(env, "DEFAULT_PORT", 11434);
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

  const vp = validatePort(body.port, defaultPort);
  if (!vp.ok) return json({ error: vp.error }, 400, request, env);

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

  const result = await probeOllama(targetHost, vp.port, timeoutMs);

  // Record aggregates asynchronously where possible
  ctx.waitUntil(
    Promise.all([
      recordCheckResult(env, {
        exposed: result.exposed,
        models: result.models,
      }),
      logAbuse(env, {
        action: "check",
        result: result.exposed ? "exposed" : "not_exposed",
        clientIp: ip,
        target: mode === "override" ? targetHost : null,
        override: mode === "override",
        meta: {
          mode,
          port: vp.port,
          status: result.status,
          latency_ms: result.latency_ms,
        },
      }),
    ])
  );

  return json(
    {
      ok: true,
      mode,
      // Never echo full client IP for own mode in detail beyond confirmation
      target: mode === "override" ? targetHost : "your_egress_ip",
      port: vp.port,
      exposed: result.exposed,
      auth_required: result.auth_required,
      latency_ms: result.latency_ms,
      models: result.exposed ? result.models : [],
      error: result.error || null,
      guidance: result.exposed
        ? "This host answered /api/ps without auth. Bind to localhost, put a reverse proxy with auth in front, and review the defensive checklist."
        : "No unauthenticated Ollama /api/ps response observed (filtered, down, or authenticated).",
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

async function handleAdminAllowlist(request, env) {
  const token = request.headers.get("X-Admin-Token") || "";
  const expected = env.ADMIN_SYNC_TOKEN || "";
  if (!expected || token !== expected) {
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
