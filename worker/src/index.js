/**
 * LeakyCompute API Worker
 * Public:  GET /v1/health, GET /v1/stats, POST /v1/check
 * Lab:     GET /v1/research/me, GET /v1/research/catalog,
 *          GET /v1/research/lab/{catalog,map,validation,host}
 * Admin:   POST /v1/admin/allowlist, /v1/admin/exclusions,
 *          /v1/admin/discovery/{ingest,sweep,lease,permit,complete};
 *          GET /v1/admin/exclusions, /v1/admin/control/health,
 *          /v1/admin/discovery/hits
 * Cron:    I-26 retention sweep (see scheduled() and [triggers] in wrangler.toml)
 *
 * Raw addresses leave this Worker only through the Access-gated research lab
 * and the admin-token routes; every public route above returns aggregates
 * (I-14). Safe probes only. No mass scan. No exploit payloads.
 */
import { json, noContent, publicJson } from "./lib/cors.js";
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
  matchAllowEntry,
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
  reconcileCorpusCounts,
  RECONCILE_ADMIN_MAX_SCAN,
  RETENTION_DAYS,
  migrationHostPage,
  migrationAttemptPage,
} from "./lib/discovery.js";
import { enrichServicesWithOsv } from "./lib/osv.js";
import { routeLab } from "./lib/lab.js";
import {
  completionOutcome,
  runDiscoveryPermit,
  runHostedPermit,
} from "./lib/socket_probe.js";
export { DiscoveryControlPlane } from "./control_plane.js";

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

      if (path === "/v1/admin/discovery/reconcile" && request.method === "POST") {
        return handleReconcile(request, env);
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

      // Dark control-plane routes. They can persist/consume permission state,
      // but neither route sends a target request and both production traffic
      // kill switches remain off.
      if (path === "/v1/admin/control/health" && request.method === "GET") {
        return handleControlHealth(request, env);
      }

      if (path === "/v1/admin/control/migrate" && request.method === "POST") {
        return handleControlMigration(request, env);
      }

      if (path === "/v1/admin/control/reconcile" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/reconcile/run");
      }

      if (path === "/v1/admin/control/retention" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/retention/run");
      }

      if (path === "/v1/admin/control/purge" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/purge/resume");
      }

      if (path === "/v1/admin/control/hosts" && request.method === "GET") {
        return handleControlPage(request, env, "/hosts/page");
      }

      if (path === "/v1/admin/control/hosts" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/hosts/upsert");
      }

      if (path === "/v1/admin/control/attempts/import" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/attempts/import");
      }

      if (path === "/v1/admin/control/attempts" && request.method === "GET") {
        return handleControlPage(request, env, "/attempts/page");
      }

      if (path === "/v1/admin/control/expiring" && request.method === "GET") {
        return handleControlPage(request, env, "/hosts/expiring");
      }

      if (path === "/v1/admin/control/retire" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/hosts/retire");
      }

      if (path === "/v1/admin/control/canary" && request.method === "POST") {
        return handleOwnedCanary(request, env);
      }

      if (path === "/v1/admin/control/exclusions" && request.method === "POST") {
        return handleControlMaintenance(request, env, "/exclusions/add");
      }

      if (path === "/v1/admin/control/aggregates" && request.method === "GET") {
        if (!requireAdmin(request, env)) return json({ error: "unauthorized" }, 401, request, env);
        const result = await controlCall(env, "/aggregates/current", { method: "GET" });
        return json(result.body, result.status, request, env);
      }

      if (path === "/v1/admin/discovery/lease" && request.method === "POST") {
        return handleControlPost(request, env, "/lease/acquire");
      }

      if (path === "/v1/admin/discovery/permit" && request.method === "POST") {
        return handleControlPost(request, env, "/permit/consume");
      }

      if (path === "/v1/admin/discovery/complete" && request.method === "POST") {
        return handleControlPost(request, env, "/lease/complete");
      }

      if (path === "/v1/admin/discovery/probe" && request.method === "POST") {
        return handleDiscoveryProbe(request, env);
      }

      return json({ error: "not_found" }, 404, request, env);
    } catch (err) {
      const requestId = crypto.randomUUID();
      console.error("worker request failed", {
        request_id: requestId,
        path,
        error: String(err?.message || err),
      });
      return json(
        { error: "internal_error", request_id: requestId },
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
    if (env.CONTROL_PLANE_READY === "true" && env.DISCOVERY_CONTROL) {
      ctx.waitUntil((async () => {
        const retention = await controlCall(env, "/retention/run", { body: {} });
        if (retention.status !== 200 || retention.body.ok === false) {
          throw new Error(`durable retention failed: ${retention.body.error || retention.status}`);
        }
        let reconciliation;
        do {
          reconciliation = await controlCall(env, "/reconcile/run", { body: { limit: 500 } });
          if (reconciliation.status !== 200 || reconciliation.body.ok === false) {
            throw new Error(`durable reconciliation failed: ${reconciliation.body.error || reconciliation.status}`);
          }
        } while (!reconciliation.body.complete && !reconciliation.body.restarted);
      })().catch((err) => console.error("durable maintenance failed:", err?.message || err)));
      return;
    }
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
        // Reconcile after the sweep, so the recount reflects the deletions it
        // just made rather than the state before them.
        .then(() => reconcileCorpusCounts(env))
        .then((r) => {
          if (!r?.ok) {
            throw new Error(`aggregate reconciliation failed: ${r?.reason || "unknown"}`);
          }
          if (!r.complete) {
            console.log(`aggregate reconciliation partial: ${r.scanned_total}/${r.total}`);
          } else if (r.drift) {
            console.log(`aggregates reconciled: ${r.reverified_before} -> ${r.reverified_after} (drift ${r.drift})`);
          }
        })
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
  const url = new URL(request.url);
  // Workers Caching keys by URL. Refuse alternate query/trailing-slash forms
  // before touching the limiter or KV so attacker-controlled URLs cannot force
  // an unbounded number of cold cache variants.
  if (url.pathname !== "/v1/stats" || url.search) {
    return publicJson({ error: "canonical_stats_url_required" }, 400);
  }

  // Cache hits are served before the Worker runs. This binding protects the
  // remaining cold misses and explicit cache-bypass requests without spending
  // the KV allowance that exclusions, authorization and retention depend on.
  // The route-wide key is intentional: Cloudflare advises against client-IP
  // keys because legitimate users may share an egress address.
  if (!env.STATS_RATE_LIMITER) {
    if (env.ENVIRONMENT === "production") {
      return publicJson({ error: "stats_temporarily_unavailable" }, 503);
    }
  } else {
    try {
      const limited = await env.STATS_RATE_LIMITER.limit({ key: "public-stats" });
      if (!limited?.success) {
        return publicJson(
          { error: "rate_limited", scope: "public_stats" },
          429,
          { "Retry-After": "60" }
        );
      }
    } catch {
      // Failing open would restore the unauthenticated KV-read amplifier this
      // boundary exists to remove.
      return publicJson({ error: "stats_temporarily_unavailable" }, 503);
    }
  }

  const live = await getLiveStats(env);
  let authoritative = null;
  if (env.CONTROL_PLANE_READY === "true") {
    const aggregate = await controlCall(env, "/aggregates/current", { method: "GET" });
    if (aggregate.status !== 200 || aggregate.body.ok === false) {
      return publicJson({ error: "stats_temporarily_unavailable" }, 503);
    }
    authoritative = aggregate.body;
  }
  const payload = await publicStatsPayload(env, live, { authoritative });
  payload.methodology = SNAPSHOT_NOTE;
  return publicJson(payload, 200, {
    "Cache-Control": "public, max-age=30",
    "Cloudflare-CDN-Cache-Control": "public, max-age=60",
    "Cache-Tag": "leakycompute-stats",
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
  const legacyTestTransport =
    env.ENVIRONMENT !== "production" && env.LEGACY_TEST_TRANSPORT === "true";
  // Cloudflare Workers' global fetch cannot target IP literals directly. The
  // default self-check target is the caller's IP, so enabling this without a
  // separate address-pinning probe service produces universal false negatives.
  // Fail visibly instead of presenting a platform refusal as a clean result.
  if (
    env.HOSTED_CHECKS_ENABLED !== "true" ||
    env.PROBE_SERVICE_ENABLED !== "true" ||
    env.CONTROL_PLANE_READY !== "true"
  ) {
    if (legacyTestTransport && env.HOSTED_CHECKS_ENABLED === "true") {
      // Unit/integration fixtures below use localhost HTTP servers. This branch
      // is unreachable in production and exists only to retain those tests
      // while production uses cloudflare:sockets.
    } else {
    return json(
      {
        error: "hosted_checks_temporarily_disabled",
        message:
          "Hosted checks are temporarily disabled until the durable permission " +
          "ledger and address-pinned probe runtime are both ready. Use the local " +
          "defensive CLI for infrastructure you control.",
      },
      503,
      request,
      env
    );
    }
  }

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
  const authorized = body.authorized === true;

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
    // Public overrides are suspended until every address-level opt-out can be
    // enforced, including ASN exclusions. The Worker has no trusted target-IP
    // to ASN mapping, so allowing this request would let a caller route around
    // an operator's ASN-wide removal request (I-25). Use the local CLI inside
    // the operator's own boundary in the meantime.
    return json(
      {
        error: "override_temporarily_disabled",
        message:
          "Checks of a different address are temporarily disabled while ASN-wide " +
          "opt-out enforcement is completed. Run the local CLI for infrastructure you control.",
      },
      403,
      request,
      env
    );
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
    services = [...new Set(
      body.services
        .map((s) => String(s).toLowerCase().trim())
        .filter((s) => TIER1.includes(s))
    )];
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
      if (TIER1.includes(k)) ports[k] = v;
    }
  }
  if (body.port != null && body.port !== "" && ports.ollama == null) {
    ports.ollama = body.port;
  }

  // Each service gets its own pre-committed lease and one-time permit. The
  // permit is consumed immediately before the TCP socket opens, so a crash,
  // replay, late opt-out, or overlapping request cannot emit unaccounted
  // traffic. The destination and path come back from the durable authority.
  let rawResults;
  if (legacyTestTransport) {
    const global = await consume(env, "global:check", intEnv(env, "RL_GLOBAL_DAY_MAX", 800), 86400);
    const window = await consume(
      env,
      `own:${ip}`,
      intEnv(env, "RL_OWN_MAX", 3),
      intEnv(env, "RL_OWN_WINDOW_SEC", 900)
    );
    const daily = await consume(env, `own_day:${ip}`, intEnv(env, "RL_OWN_DAY_MAX", 12), 86400);
    if (!global.ok || !window.ok || !daily.ok) {
      return json({ error: "rate_limited", scope: global.ok ? "own_ip" : "global" }, 429, request, env);
    }
    const legacyRun = await runChecks(targetHost, { services, ports, timeoutMs });
    if (!legacyRun.ok) {
      return json({
        error: legacyRun.error,
        service: legacyRun.service,
        allowed_ports: legacyRun.allowed,
      }, 400, request, env);
    }
    rawResults = legacyRun.results;
  } else {
  const probeOne = async (service) => {
    const lease = await controlCall(env, "/lease/acquire", {
      body: {
        purpose: "hosted_self",
        ip: targetHost,
        asn: request.cf?.asn || null,
        service,
        port: ports[service],
      },
    });
    if (lease.status !== 200) return { gate: lease };
    const consumed = await controlCall(env, "/permit/consume", {
      body: { permit_id: lease.body.permit_id },
    });
    if (consumed.status !== 200) return { gate: consumed };
    const run = await runHostedPermit(consumed.body, { timeoutMs });
    const result = run.result || {
      service,
      port: consumed.body.port,
      detected: false,
      exposed: false,
      error: run.error || "probe_runtime_failed",
      error_class: run.error_class || "platform_error",
      findings: [],
      remediation: [],
    };
    const outcome = completionOutcome(result);
    await controlCall(env, "/lease/complete", {
      body: { lease_id: consumed.body.lease_id, outcome },
    });
    return { result, outcome };
  };

  const runs = [];
  for (const service of services) {
    const item = await probeOne(service);
    if (item.gate) {
      const error = item.gate.body?.error || "probe_permission_denied";
      if (item.gate.status === 429) {
        return json({ error: "rate_limited", scope: item.gate.body.scope }, 429, request, env);
      }
      return json({ error, message: "No target traffic was sent." }, item.gate.status, request, env);
    }
    runs.push(item);
  }
    rawResults = runs.map((item) => item.result);
  }

  // Tier-2: attach OSV.dev vulns when we have a confirmed version string.
  // enrichServicesWithOsv also merges top hits into svc.findings, so
  // overallSeverity() already reflects version-aware CVE/GHSA severity.
  const results = await enrichServicesWithOsv(rawResults, env);
  const anyExposed = results.some((r) => r.exposed);
  const platformFailure = results.some((r) =>
    r.error_class === "platform_error" || r.error_class === "authorization_error"
  );
  const inconclusive = platformFailure || results.some((r) => r.error_class === "target_error");
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
      result: anyExposed ? "exposed" : inconclusive ? "inconclusive" : "not_exposed",
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
  if (exposedServices.length && !legacyTestTransport) {
    const authoritative = await controlCall(env, "/hosts/upsert", {
      body: {
        records: [{
          ip: targetHost,
          port: exposedServices[0].port,
          ports: exposedServices.map((r) => r.port),
          stack: exposedServices[0].service,
          stacks: exposedServices.map((r) => r.service),
          source: "public_self_check",
          asn: request.cf?.asn || null,
          last_seen: new Date().toISOString(),
        }],
      },
    });
    if (authoritative.status !== 200 || authoritative.body.accepted !== 1) {
      return json({ error: "result_storage_failed", result_preserved: false }, 503, request, env);
    }
  }
  if (exposedServices.length) {
    // Store the probed host in KV as a compatibility cache for the lab during
    // the cutover. Durable SQLite above is authoritative in production.
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
      conclusive: !inconclusive,
      services: results,
      guidance: anyExposed
        ? "At least one AI service answered an unauthenticated read from the public internet. Work through the per-service remediation below."
        : inconclusive
          ? "The check was inconclusive for at least one service. Do not treat this as a clean result; review the per-service errors or run the local checker."
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
    platformFailure ? 503 : 200,
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
  // Match against every identity the assertion presented, not just the first.
  const match = await matchAllowEntry(env, identity.candidates || [identity.login]);
  const allowed = !!match;
  const entry = match?.entry || null;
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
      matched_as: match?.matched || null,
      // A denial that does not say which name was checked is a support ticket.
      // This is the field whose absence cost an afternoon: the approval issue
      // records a GitHub handle, the assertion may present an email, and the
      // researcher had no way to see that those disagreed.
      identities_presented: allowed ? undefined : identity.candidates,
      hint: allowed
        ? undefined
        : "Signed in, but none of the identities above are on the researcher " +
          "allowlist. The approval issue records a GitHub username; your Access " +
          "assertion may present an email instead. Quote this list on the access " +
          "issue and a maintainer can add the right one.",
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
  // Same rule as every other gate: match all presented identities, and say
  // which ones were checked when refusing.
  const catalogMatch = await matchAllowEntry(
    env,
    identity.candidates || [identity.login]
  );
  if (!catalogMatch) {
    return json(
      {
        error: "forbidden",
        login: identity.login,
        identities_presented: identity.candidates,
      },
      403,
      request,
      env
    );
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

function controlStub(env) {
  if (!env.DISCOVERY_CONTROL) return null;
  const id = env.DISCOVERY_CONTROL.idFromName("global");
  return env.DISCOVERY_CONTROL.get(id);
}

async function controlCall(env, path, { method = "POST", body } = {}) {
  const stub = controlStub(env);
  if (!stub) return { status: 503, body: { error: "control_plane_unavailable" } };
  const response = await stub.fetch(`https://control.internal${path}`, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    payload = { error: "invalid_control_plane_response" };
  }
  return { status: response.status, body: payload };
}

async function handleControlHealth(request, env) {
  if (!requireControlMaintenance(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const result = await controlCall(env, "/health", { method: "GET" });
  return json(result.body, result.status, request, env);
}

function requireControlMaintenance(request, env) {
  if (requireAdmin(request, env)) return true;
  const supplied = request.headers.get("X-Migration-Token") || "";
  const expected = env.CONTROL_MIGRATION_TOKEN || "";
  return !!(supplied && expected && supplied === expected);
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function handleControlMaintenance(request, env, path) {
  if (!requireControlMaintenance(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const result = await controlCall(env, path, { body: await readJsonBody(request) });
  return json(result.body, result.status, request, env);
}

async function handleControlPage(request, env, path) {
  if (!requireAdmin(request, env)) return json({ error: "unauthorized" }, 401, request, env);
  if (env.CONTROL_PLANE_READY !== "true") {
    return json({ error: "control_plane_not_ready" }, 503, request, env);
  }
  const url = new URL(request.url);
  const query = new URLSearchParams();
  if (url.searchParams.get("cursor")) query.set("cursor", url.searchParams.get("cursor"));
  query.set("limit", String(Math.min(Number(url.searchParams.get("limit")) || 100, 500)));
  if (url.searchParams.get("days")) query.set("days", url.searchParams.get("days"));
  const result = await controlCall(env, `${path}?${query}`, { method: "GET" });
  return json(result.body, result.status, request, env);
}

async function handleControlMigration(request, env) {
  if (!requireControlMaintenance(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  const asked = await readJsonBody(request);
  const statusResult = await controlCall(env, "/migration/status", { method: "GET" });
  if (statusResult.status !== 200) return json(statusResult.body, statusResult.status, request, env);
  const status = statusResult.body;

  const exclusions = await loadExclusions(env);
  const exclusionResult = await controlCall(env, "/exclusions/add", {
    body: { entries: exclusions, meta: { source: "kv_migration" } },
  });
  if (exclusionResult.status !== 200) {
    return json({ ok: false, phase: "exclusions", ...exclusionResult.body }, exclusionResult.status, request, env);
  }
  for (const job of exclusionResult.body.purge_jobs || []) {
    if (job.status !== "complete") {
      await controlCall(env, "/purge/resume", { body: { id: job.id, limit: 500 } });
    }
  }

  let importedHosts = 0;
  let importedAttempts = 0;
  let hostsComplete = status.hosts_complete;
  let attemptsComplete = status.attempts_complete;
  let hostCursor = status.host_cursor || "";
  let attemptCursor = status.attempt_cursor || "";

  if (!hostsComplete) {
    const page = await migrationHostPage(env, { cursor: hostCursor, limit: asked.host_limit || 40 });
    if (page.records.length) {
      const imported = await controlCall(env, "/hosts/upsert", { body: { records: page.records } });
      if (imported.status !== 200) {
        return json({ ok: false, phase: "hosts", ...imported.body }, imported.status, request, env);
      }
      importedHosts = Number(imported.body.accepted || 0);
    }
    hostCursor = page.next_cursor || hostCursor;
    hostsComplete = page.complete;
  }

  if (!attemptsComplete) {
    const page = await migrationAttemptPage(env, { cursor: attemptCursor, limit: asked.attempt_limit || 200 });
    if (page.attempts.length) {
      const imported = await controlCall(env, "/attempts/import", { body: { attempts: page.attempts } });
      if (imported.status !== 200) {
        return json({ ok: false, phase: "attempts", ...imported.body }, imported.status, request, env);
      }
      importedAttempts = Number(imported.body.imported || 0);
    }
    attemptCursor = page.next_cursor || attemptCursor;
    attemptsComplete = page.complete;
  }

  const checkpoint = await controlCall(env, "/migration/checkpoint", {
    body: {
      host_cursor: hostCursor,
      attempt_cursor: attemptCursor,
      hosts_complete: hostsComplete,
      attempts_complete: attemptsComplete,
      imported_hosts: importedHosts,
      imported_attempts: importedAttempts,
    },
  });

  const reconciliation = await controlCall(env, "/reconcile/run", { body: { limit: 500 } });
  const health = await controlCall(env, "/health", { method: "GET" });
  let completion = null;
  if (
    checkpoint.body.hosts_complete && checkpoint.body.attempts_complete &&
    reconciliation.body.complete && Number(health.body.pending_purges || 0) === 0
  ) {
    completion = await controlCall(env, "/migration/complete", {
      body: {
        expected_hosts: Number(health.body.hosts),
        expected_attempts: Number(health.body.attempts),
      },
    });
  }
  return json({
    ok: true,
    phase: completion?.body?.ok ? "complete" : "migrating",
    migration: checkpoint.body,
    reconciliation: reconciliation.body,
    control: health.body,
    completion: completion?.body || null,
  }, 200, request, env);
}

async function handleOwnedCanary(request, env) {
  if (!requireControlMaintenance(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  if (env.CONTROL_PLANE_READY !== "true" || env.CANARY_PROBE_ENABLED !== "true") {
    return json({ error: "owned_canary_disabled" }, 503, request, env);
  }
  const ip = String(env.CANARY_TARGET_IP || "");
  const lease = await controlCall(env, "/lease/acquire", {
    body: {
      purpose: "owned_canary",
      ip,
      asn: "AS-UNKNOWN",
      service: "owned_canary",
      port: 10000,
    },
  });
  if (lease.status !== 200) return json(lease.body, lease.status, request, env);
  const consumed = await controlCall(env, "/permit/consume", {
    body: { permit_id: lease.body.permit_id },
  });
  if (consumed.status !== 200) return json(consumed.body, consumed.status, request, env);
  const run = await runDiscoveryPermit(consumed.body, {
    timeoutMs: Math.min(intEnv(env, "CHECK_TIMEOUT_MS", 2500), 5000),
  });
  const result = run.result || {
    exposed: false,
    answered: false,
    error: run.error || "probe_runtime_failed",
    error_class: run.error_class || "platform_error",
  };
  const markerOk = result.status === 200 && result.canary_marker === "owned";
  const outcome = markerOk ? "exposed" : completionOutcome(result);
  await controlCall(env, "/lease/complete", {
    body: { lease_id: consumed.body.lease_id, outcome },
  });
  return json({
    ok: markerOk,
    canary: "operator_owned",
    target_matched_configuration: consumed.body.ip === ip,
    destination: { port: consumed.body.port, path: "/leakycompute-owned-canary" },
    result,
  }, markerOk ? 200 : 503, request, env);
}

async function handleControlPost(request, env, path) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  if (env.CONTROL_PLANE_READY !== "true") {
    return json(
      {
        error: "control_plane_not_ready",
        message: "Strong-state migration and verification have not completed.",
      },
      503,
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
  const result = await controlCall(env, path, { body });
  return json(result.body, result.status, request, env);
}

async function handleDiscoveryProbe(request, env) {
  if (!requireAdmin(request, env)) return json({ error: "unauthorized" }, 401, request, env);
  if (
    env.CONTROL_PLANE_READY !== "true" ||
    env.ACTIVE_DISCOVERY_ENABLED !== "true" ||
    env.PROBE_SERVICE_ENABLED !== "true"
  ) {
    return json({ error: "active_discovery_temporarily_disabled" }, 503, request, env);
  }
  const body = await readJsonBody(request);
  if (!body.permit_id) return json({ error: "permit_id_required" }, 400, request, env);
  const consumed = await controlCall(env, "/permit/consume", {
    body: { permit_id: body.permit_id },
  });
  if (consumed.status !== 200) return json(consumed.body, consumed.status, request, env);

  const run = await runDiscoveryPermit(consumed.body, {
    timeoutMs: intEnv(env, "CHECK_TIMEOUT_MS", 2500),
  });
  const result = run.result || {
    exposed: false,
    answered: false,
    error: run.error || "probe_runtime_failed",
    error_class: run.error_class || "platform_error",
  };
  const outcome = completionOutcome(result);
  await controlCall(env, "/lease/complete", {
    body: { lease_id: consumed.body.lease_id, outcome },
  });

  if (outcome === "exposed") {
    await controlCall(env, "/hosts/upsert", {
      body: {
        records: [{
          ip: consumed.body.ip,
          port: consumed.body.port,
          stack: consumed.body.service,
          version: result.version || null,
          source: `public_index:${consumed.body.provenance?.source || "unknown"}`,
          index_observed_at: consumed.body.provenance?.observed_at || null,
          asn: consumed.body.asn,
          last_seen: new Date().toISOString(),
        }],
      },
    });
  }
  return json({
    ok: true,
    lease_id: consumed.body.lease_id,
    outcome,
    result,
  }, 200, request, env);
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
    // Forwarded so an approval can record the identity Access will actually
    // assert. Without this the field was accepted by the API and silently
    // dropped before it reached storage — the approval would look successful
    // and the researcher would still be locked out.
    aliases: Array.isArray(body.aliases) ? body.aliases : [],
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

  // During the dark migration KV remains the live authority, but every newly
  // accepted exclusion is mirrored into the strong control plane immediately.
  // A mirror failure is reported; it never rolls back the already-active KV
  // exclusion while target traffic is disabled.
  let control_plane = { ok: true, accepted: 0 };
  const authoritativeExclusions = await loadExclusions(env);
  if (authoritativeExclusions.length) {
    try {
      const mirrored = await controlCall(env, "/exclusions/add", {
        body: {
          entries: authoritativeExclusions,
          meta: {
            issue_number: body.issue_number ?? null,
            source: body.source || "removal-request",
          },
        },
      });
      control_plane = {
        ok: mirrored.status >= 200 && mirrored.status < 300 && mirrored.body.ok !== false,
        status: mirrored.status,
        accepted: mirrored.body.accepted?.length || 0,
        error: mirrored.body.error || null,
        purges: [],
      };
      for (const job of mirrored.body.purge_jobs || []) {
        let state = { job };
        for (let i = 0; i < 20 && state.job?.status !== "complete"; i++) {
          const step = await controlCall(env, "/purge/resume", {
            body: { id: job.id, limit: 500 },
          });
          if (step.status !== 200) {
            state = { job, error: step.body.error || `status_${step.status}` };
            break;
          }
          state = step.body;
        }
        control_plane.purges.push(state);
        if (state.job?.status !== "complete" || !state.receipt?.verified_zero_matches) {
          control_plane.ok = false;
        }
      }
    } catch (error) {
      control_plane = { ok: false, accepted: 0, error: String(error?.message || error) };
    }
  }

  const purged = await purgeExcludedRecords(env);

  // Rejected lines are reported, never silently dropped: an operator who
  // fat-fingers a CIDR must find out, not assume they are excluded.
  return json({ ok: true, ...result, control_plane, purged }, 200, request, env);
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
/**
 * Recount the published aggregates from the records themselves. Every counter
 * we publish is derived and can only drift downward when a write fails; without
 * this there is no way back to the truth.
 */
async function handleReconcile(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "unauthorized" }, 401, request, env);
  }
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const requested = Number(body.limit);
  const limit = Number.isFinite(requested) && requested > 0
    ? Math.min(Math.floor(requested), RECONCILE_ADMIN_MAX_SCAN)
    : RECONCILE_ADMIN_MAX_SCAN;
  const res = await reconcileCorpusCounts(env, { limit });
  return json({ ok: true, ...res }, 200, request, env);
}

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
