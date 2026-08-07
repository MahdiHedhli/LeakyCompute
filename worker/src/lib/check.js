/**
 * Safe Ollama exposure probe.
 * ONLY GET /api/ps (and optional banner GET /).
 * Never sends path-traversal, pull, or generate payloads.
 */

const IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
// simplified IPv6 check
const IPV6 = /^[0-9a-fA-F:]+$/;

export function isPrivateOrLocal(ip) {
  if (!ip) return true;
  const v = ip.toLowerCase();
  if (v === "localhost" || v === "::1" || v === "0.0.0.0") return true;
  if (IPV4.test(v)) {
    const p = v.split(".").map(Number);
    if (p[0] === 10) return true;
    if (p[0] === 127) return true;
    if (p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  }
  if (v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80")) return true;
  return false;
}

export function validateTarget(host) {
  if (!host || typeof host !== "string") {
    return { ok: false, error: "missing_target" };
  }
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (h.length > 253) return { ok: false, error: "target_too_long" };
  if (h.includes("/") || h.includes(" ") || h.includes("\\")) {
    return { ok: false, error: "invalid_target" };
  }
  // block URL schemes / SSRF tricks in host field
  if (/^[a-z]+:/.test(h) || h.includes("@")) {
    return { ok: false, error: "invalid_target" };
  }
  if (IPV4.test(h) || (h.includes(":") && IPV6.test(h))) {
    return { ok: true, host: h, kind: "ip" };
  }
  // hostname: labels
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(h)) {
    return { ok: false, error: "invalid_hostname" };
  }
  return { ok: true, host: h, kind: "hostname" };
}

export function validatePort(port, fallback = 11434) {
  const p = port == null || port === "" ? fallback : Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    return { ok: false, error: "invalid_port" };
  }
  return { ok: true, port: p };
}

/**
 * Probe target for unauthenticated Ollama /api/ps.
 */
export async function probeOllama(host, port, timeoutMs = 3000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  const base = host.includes(":") && !host.startsWith("[") && IPV6.test(host)
    ? `http://[${host}]:${port}`
    : `http://${host}:${port}`;

  try {
    const resp = await fetch(`${base}/api/ps`, {
      method: "GET",
      signal: controller.signal,
      redirect: "manual",
      headers: { Accept: "application/json", "User-Agent": "LeakyCompute-SafeProbe/1.0" },
    });
    const latency = Date.now() - started;
    if (resp.status === 401 || resp.status === 403) {
      return {
        exposed: false,
        auth_required: true,
        status: resp.status,
        latency_ms: latency,
        models: [],
      };
    }
    if (!resp.ok) {
      return {
        exposed: false,
        auth_required: false,
        status: resp.status,
        latency_ms: latency,
        models: [],
      };
    }
    let models = [];
    try {
      const data = await resp.json();
      const list = Array.isArray(data?.models) ? data.models : [];
      models = list.slice(0, 25).map((m) => ({
        name: m.name || m.model || "unknown",
        size: m.size || null,
      }));
    } catch {
      // non-json but 200 — still interesting
    }
    return {
      exposed: true,
      auth_required: false,
      status: resp.status,
      latency_ms: latency,
      models,
    };
  } catch (err) {
    return {
      exposed: false,
      auth_required: false,
      status: 0,
      latency_ms: Date.now() - started,
      models: [],
      error: err?.name === "AbortError" ? "timeout" : "unreachable",
    };
  } finally {
    clearTimeout(timer);
  }
}
