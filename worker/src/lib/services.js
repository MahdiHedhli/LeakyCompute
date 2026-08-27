/**
 * Tier-1 service definitions + read-only probe engine.
 *
 * HARD RULE: every request emitted from this module is a GET against a
 * metadata / health / version / listing endpoint. Nothing here submits a job,
 * pulls a model, sends a prompt, or otherwise changes state on a target.
 * We report that an endpoint answers unauthenticated requests; we never send
 * one to prove impact.
 *
 * Each service follows the same flow:
 *   confirm  -> is this actually the service? (and what version?)
 *   exposure -> does the sensitive read-only endpoint answer without auth?
 *
 * The exposure probe only runs if confirm succeeded, so we never spray
 * requests at hosts that aren't running the service.
 */

const SEVERITY_ORDER = ["none", "info", "low", "medium", "high", "critical"];

export function severityRank(sev) {
  const i = SEVERITY_ORDER.indexOf(sev);
  return i < 0 ? 0 : i;
}

export function maxSeverity(list) {
  let best = "none";
  for (const sev of list) {
    if (severityRank(sev) > severityRank(best)) best = sev;
  }
  return best;
}

/**
 * Read at most maxBytes of a response body.
 * Targets are untrusted — in override mode a hostile host could stream an
 * unbounded body at us. Cap it and drop the rest.
 */
async function readCapped(resp, maxBytes = 32 * 1024) {
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const chunks = [];
  let received = 0;
  try {
    while (received < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
    }
  } catch {
    // truncated / aborted read — use whatever we already have
  } finally {
    try {
      await reader.cancel();
    } catch {
      // already closed
    }
  }
  const out = new Uint8Array(Math.min(received, maxBytes));
  let off = 0;
  for (const chunk of chunks) {
    const take = Math.min(chunk.length, out.length - off);
    if (take <= 0) break;
    out.set(chunk.subarray(0, take), off);
    off += take;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(out);
}

function parseJsonLoose(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function htmlTitle(text) {
  const m = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(text || "");
  return m ? m[1].trim() : "";
}

const IPV6_CHARS = /^[0-9a-fA-F:]+$/;

function baseUrl(host, port) {
  const isBareIpv6 = host.includes(":") && !host.startsWith("[") && IPV6_CHARS.test(host);
  return isBareIpv6 ? `http://[${host}]:${port}` : `http://${host}:${port}`;
}

/**
 * Single read-only GET with its own timeout, bounded body, and no redirect
 * following (a redirect must never take us to a different host).
 */
async function safeGet(url, { timeoutMs, maxBytes = 32 * 1024, accept, transport }) {
  if (transport) {
    return transport(url, { timeoutMs, maxBytes, accept });
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const resp = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      redirect: "manual",
      headers: {
        Accept: accept || "application/json, text/html;q=0.8, */*;q=0.5",
        "User-Agent": "LeakyCompute-SafeProbe/2.0 (+defensive self-check; read-only GET)",
      },
    });
    const text = await readCapped(resp, maxBytes);
    return {
      ok: true,
      status: resp.status,
      location: resp.headers.get("Location") || "",
      contentType: resp.headers.get("Content-Type") || "",
      text,
      json: parseJsonLoose(text),
      latency_ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      location: "",
      contentType: "",
      text: "",
      json: null,
      latency_ms: Date.now() - started,
      error: err?.name === "AbortError" ? "timeout" : "unreachable",
      error_class: "target_error",
    };
  } finally {
    clearTimeout(timer);
  }
}

function authRejected(status) {
  return status === 401 || status === 403 || status === 407;
}

/* ------------------------------------------------------------------ */
/* Service registry                                                    */
/* ------------------------------------------------------------------ */

export const SERVICES = {
  ollama: {
    id: "ollama",
    label: "Ollama",
    defaultPort: 11434,
    // Known AI ports only. This is deliberately not a general port prober.
    allowedPorts: [11434, 11435],
    confirm: [
      {
        path: "/api/version",
        // Ollama: {"version":"0.1.40"}. Ray also serves /api/version but on a
        // different port and includes ray_version — exclude it explicitly.
        match: (r) =>
          r.status === 200 &&
          r.json &&
          typeof r.json.version === "string" &&
          r.json.ray_version === undefined,
        version: (r) => r.json.version,
      },
      {
        path: "/",
        match: (r) => r.status === 200 && /ollama is running/i.test(r.text),
        version: () => null,
      },
    ],
    exposure: {
      path: "/api/tags",
      // GET only: lists locally installed models. Read-only.
      evaluate: (r) => {
        if (authRejected(r.status)) {
          return { exposed: false, authenticated: true };
        }
        if (r.status === 200 && r.json && Array.isArray(r.json.models)) {
          return {
            exposed: true,
            authenticated: false,
            models: r.json.models.slice(0, 25).map((m) => ({
              name: m.name || m.model || "unknown",
              size: typeof m.size === "number" ? m.size : null,
            })),
          };
        }
        return { exposed: false, authenticated: false };
      },
    },
    finding: {
      id: "ollama-unauth-api",
      title: "Unauthenticated Ollama API exposed",
      severity: "high",
      detail:
        "GET /api/tags returned the installed model list without credentials. " +
        "The same unauthenticated surface exposes /api/pull and /api/generate, " +
        "which allow arbitrary model pulls, inference at your expense, and — on " +
        "unpatched builds — file reads via crafted model names.",
    },
    reachableFinding: {
      id: "ollama-reachable",
      title: "Ollama reachable from the public internet",
      severity: "low",
      detail:
        "The service answered from your egress IP but rejected the unauthenticated " +
        "read. It is still publicly reachable, so it remains exposed to auth bypasses " +
        "and future unauthenticated CVEs.",
    },
    remediation: [
      "Bind Ollama to 127.0.0.1 (set OLLAMA_HOST=127.0.0.1:11434) instead of 0.0.0.0.",
      "If remote access is required, front it with a reverse proxy enforcing TLS and an API key or mTLS.",
      "Restrict port 11434 at the host firewall and cloud security group to known source ranges.",
      "Run the container as a non-root user with a read-only rootfs and no route to cloud metadata (169.254.169.254).",
      "Alert on /api/pull spikes and on model names containing '../', absolute paths, or link-local IPs.",
    ],
  },

  ray: {
    id: "ray",
    label: "Ray",
    defaultPort: 8265,
    allowedPorts: [8265, 8266],
    confirm: [
      {
        path: "/api/version",
        // Ray dashboard: {"version":"...","ray_version":"2.9.0","ray_commit":"..."}
        match: (r) => r.status === 200 && r.json && typeof r.json.ray_version === "string",
        version: (r) => r.json.ray_version,
      },
      {
        path: "/",
        match: (r) => r.status === 200 && /ray dashboard/i.test(htmlTitle(r.text) + r.text),
        version: () => null,
      },
    ],
    exposure: {
      path: "/api/jobs/",
      // GET only: lists submitted jobs. We never POST a job.
      evaluate: (r) => {
        if (authRejected(r.status)) {
          return { exposed: false, authenticated: true };
        }
        // Ray returns a JSON array of job records (often empty on an idle cluster).
        if (r.status === 200 && Array.isArray(r.json)) {
          return { exposed: true, authenticated: false, jobs_visible: r.json.length };
        }
        return { exposed: false, authenticated: false };
      },
    },
    finding: {
      id: "ray-unauth-jobs-api",
      title: "Ray Jobs API exposed without authentication",
      severity: "critical",
      detail:
        "GET /api/jobs/ answered without credentials. Ray ships no authentication by " +
        "design, so anyone who can reach this port can submit jobs — which is remote " +
        "code execution on the cluster. These are the preconditions for CVE-2023-48022 " +
        "(ShadowRay). The CVE is disputed because the vendor considers the missing auth " +
        "intended behaviour, so this is flagged on your exposed configuration, not on " +
        "your Ray version — upgrading will not fix it.",
    },
    reachableFinding: {
      id: "ray-reachable",
      title: "Ray dashboard reachable from the public internet",
      severity: "medium",
      detail:
        "The Ray dashboard answered from your egress IP. Even where the Jobs API did " +
        "not return a list, Ray's dashboard is not designed to be internet-facing.",
    },
    remediation: [
      "Never expose the Ray dashboard or Jobs API to the internet — Ray has no built-in authentication.",
      "Bind the dashboard to localhost (ray start --dashboard-host=127.0.0.1) and reach it over an SSH tunnel or VPN.",
      "Place the cluster in a private subnet; restrict 8265 to trusted CIDRs in the security group.",
      "If remote access is needed, front the dashboard with an authenticating reverse proxy or an identity-aware proxy.",
      "Alert on job submissions from unexpected source addresses.",
    ],
  },

  jupyter: {
    id: "jupyter",
    label: "Jupyter",
    defaultPort: 8888,
    allowedPorts: [8888, 8889, 8890],
    confirm: [
      {
        path: "/api/status",
        // jupyter_server exposes /api/status unauthenticated for health checks:
        // {"started":...,"last_activity":...,"connections":0,"kernels":0,"version":"2.14.0"}
        match: (r) =>
          (r.status === 200 && r.json && typeof r.json.started === "string") ||
          (authRejected(r.status) && /jupyter|token|forbidden/i.test(r.text)),
        version: (r) => (r.json && r.json.version) || null,
      },
      {
        path: "/",
        match: (r) => {
          if (r.status === 200) return /jupyter/i.test(htmlTitle(r.text) + r.text.slice(0, 2048));
          // A redirect to the token login page is itself a Jupyter fingerprint.
          if (r.status >= 300 && r.status < 400) return /\/login/i.test(r.location);
          return false;
        },
        version: () => null,
      },
    ],
    exposure: {
      path: "/tree",
      // GET only: the file-tree UI. Reaching it without a token redirect means
      // the notebook server accepts unauthenticated sessions.
      evaluate: (r) => {
        // Redirect to /login => token auth is enforced. This is the good case.
        if (r.status >= 300 && r.status < 400 && /\/login/i.test(r.location)) {
          return { exposed: false, authenticated: true };
        }
        if (authRejected(r.status)) {
          return { exposed: false, authenticated: true };
        }
        if (r.status === 200) {
          // Some builds return 200 but render the login form instead of redirecting.
          const looksLikeLogin =
            /password_input|token=|<input[^>]+type=["']password/i.test(r.text) ||
            /log\s*in to jupyter/i.test(r.text);
          if (looksLikeLogin) return { exposed: false, authenticated: true };
          return { exposed: true, authenticated: false };
        }
        return { exposed: false, authenticated: false };
      },
    },
    finding: {
      id: "jupyter-no-token-auth",
      title: "Jupyter reachable without token authentication",
      severity: "critical",
      detail:
        "GET /tree rendered the notebook file browser without redirecting to the token " +
        "login page. Anyone who can reach this port can open a notebook and execute " +
        "arbitrary code as the user running the server, and read every file that user can read.",
    },
    reachableFinding: {
      id: "jupyter-reachable",
      title: "Jupyter reachable from the public internet",
      severity: "low",
      detail:
        "The notebook server answered from your egress IP but enforced token or password " +
        "auth. It is still publicly reachable and exposed to token brute-forcing and to " +
        "any future pre-auth vulnerability.",
    },
    remediation: [
      "Bind Jupyter to 127.0.0.1 (ServerApp.ip = '127.0.0.1') and reach it over an SSH tunnel.",
      "Never run with --ServerApp.token='' or --ServerApp.password='' on a routable interface.",
      "If remote access is required, front it with a reverse proxy enforcing TLS and SSO.",
      "Restrict port 8888 at the host firewall and cloud security group.",
      "Run the notebook as an unprivileged user so a compromise does not hand over the host.",
    ],
  },
};

export const TIER1 = ["ollama", "ray", "jupyter"];

/**
 * The unattended discovery runner is intentionally broader than the public
 * self-check, but every lane is still pinned to one reviewed, read-only GET.
 * This registry is the authority used by both the durable lease gate and the
 * socket runtime. A runner-supplied path or port is never trusted.
 */
export const DISCOVERY_PROFILES = Object.freeze({
  // Production egress verification only. The control plane refuses this
  // profile for discovery/hosted purposes and binds it to CANARY_TARGET_IP.
  owned_canary: { ports: [8443], path: "/leakycompute-owned-canary" },
  ollama: { ports: [11434, 11435], path: "/api/ps" },
  jupyter: { ports: [8888, 8889, 8890], path: "/" },
  ray: { ports: [8265, 8266], path: "/api/version" },
  open_webui: { ports: [8080], path: "/api/config" },
  localai: { ports: [8080], path: "/v1/models" },
  litellm: { ports: [4000], path: "/health/liveliness" },
  vllm: { ports: [8000, 8080], path: "/v1/models" },
  openai_compat_8000: { ports: [8000], path: "/v1/models" },
  openai_compat_8080: { ports: [8080], path: "/v1/models" },
  comfyui: { ports: [8188], path: "/system_stats" },
  gradio: { ports: [7860], path: "/config" },
  mlflow: { ports: [5000], path: "/health" },
  triton: { ports: [8000], path: "/v2" },
  tensorboard: { ports: [6006], path: "/data/plugins_listing" },
});

/** Every port this checker is ever willing to touch. */
export const ALLOWED_PORTS = new Set(
  Object.values(DISCOVERY_PROFILES).flatMap((s) => s.ports)
);

/**
 * Resolve and validate a caller-supplied per-service port.
 * Only ports belonging to that service are accepted — this keeps the checker
 * from being usable as a general-purpose port prober.
 */
export function resolvePort(serviceId, requested) {
  const hosted = Object.hasOwn(SERVICES, serviceId) ? SERVICES[serviceId] : null;
  const discovery = Object.hasOwn(DISCOVERY_PROFILES, serviceId)
    ? DISCOVERY_PROFILES[serviceId]
    : null;
  const allowedPorts = hosted?.allowedPorts || discovery?.ports;
  if (!allowedPorts) return { ok: false, error: "unknown_service" };
  if (requested == null || requested === "") {
    return { ok: true, port: hosted?.defaultPort || allowedPorts[0] };
  }
  const p = Number(requested);
  if (!Number.isInteger(p)) return { ok: false, error: "invalid_port" };
  if (!allowedPorts.includes(p)) {
    return {
      ok: false,
      error: "port_not_allowed",
      allowed: allowedPorts,
    };
  }
  return { ok: true, port: p };
}

/* ------------------------------------------------------------------ */
/* Probe engine                                                        */
/* ------------------------------------------------------------------ */

/**
 * Probe one service on one port. At most 3 read-only GETs.
 * Connection failure and timeout are "not detected", never an error.
 */
export async function probeService(
  host,
  serviceId,
  port,
  { timeoutMs = 2500, transport } = {}
) {
  const svc = SERVICES[serviceId];
  const base = baseUrl(host, port);

  const result = {
    service: svc.id,
    label: svc.label,
    port,
    detected: false,
    version: null,
    exposed: false,
    authenticated: false,
    latency_ms: null,
    status: 0,
    error: null,
    error_class: null,
    findings: [],
    remediation: [],
  };

  // --- confirm -------------------------------------------------------
  let confirmed = null;
  let lastError = null;
  let lastErrorClass = null;
  for (const step of svc.confirm) {
    const r = await safeGet(`${base}${step.path}`, { timeoutMs, transport });
    if (!r.ok) {
      lastError = r.error;
      lastErrorClass = r.error_class || "target_error";
      // A transport failure on the first probe means nothing is listening;
      // trying the fallback path would just burn another timeout.
      break;
    }
    result.latency_ms = r.latency_ms;
    result.status = r.status;
    if (step.match(r)) {
      confirmed = r;
      try {
        result.version = step.version(r) || null;
      } catch {
        result.version = null;
      }
      // If the confirming response was itself an auth rejection, record that.
      if (authRejected(r.status)) result.authenticated = true;
      break;
    }
  }

  if (!confirmed) {
    result.error = lastError;
    result.error_class = lastErrorClass;
    return result;
  }
  result.detected = true;

  // --- exposure ------------------------------------------------------
  const ex = await safeGet(`${base}${svc.exposure.path}`, { timeoutMs, transport });
  if (!ex.ok) {
    // Detected but the exposure probe failed — report detection honestly and
    // do not claim anything about auth.
    result.error = ex.error;
    result.error_class = ex.error_class || "target_error";
    result.findings.push(buildReachable(svc));
    result.remediation = svc.remediation;
    return result;
  }

  result.status = ex.status;
  result.latency_ms = ex.latency_ms;
  const verdict = svc.exposure.evaluate(ex);
  result.exposed = !!verdict.exposed;
  result.authenticated = !!verdict.authenticated;
  if (verdict.models) result.models = verdict.models;
  if (typeof verdict.jobs_visible === "number") result.jobs_visible = verdict.jobs_visible;

  if (result.exposed) {
    result.findings.push({ ...svc.finding, endpoint: svc.exposure.path });
  } else {
    result.findings.push(buildReachable(svc));
  }
  result.remediation = svc.remediation;
  return result;
}

function buildReachable(svc) {
  return { ...svc.reachableFinding, endpoint: null };
}

/**
 * Probe every requested service in parallel.
 * Parallel matters: three services sequentially would exceed the request
 * wall-clock budget under a 2.5s per-probe timeout.
 */
export async function runChecks(
  host,
  { services = TIER1, ports = {}, timeoutMs = 2500, transport } = {}
) {
  // Defense in depth: callers other than index.js must not be able to amplify
  // subrequests with duplicates or inherited object keys.
  const selected = [...new Set(services)].filter((s) => Object.hasOwn(SERVICES, s));
  const resolved = [];
  for (const id of selected) {
    const rp = resolvePort(id, ports[id]);
    if (!rp.ok) return { ok: false, error: rp.error, service: id, allowed: rp.allowed };
    resolved.push({ id, port: rp.port });
  }

  const results = await Promise.all(
    resolved.map(({ id, port }) => probeService(host, id, port, { timeoutMs, transport }))
  );

  return { ok: true, results };
}

/** Overall severity across a report: the worst confirmed finding. */
export function overallSeverity(results) {
  const sevs = [];
  for (const r of results) {
    if (!r.detected) continue;
    for (const f of r.findings) sevs.push(f.severity);
  }
  return maxSeverity(sevs);
}
