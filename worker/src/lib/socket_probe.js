/**
 * Address-pinned read-only probe transport for Cloudflare Workers.
 *
 * `fetch()` cannot connect to an IP-literal URL. Workers TCP sockets can, so we
 * speak the small HTTP/1.0 subset this project needs directly. The destination
 * comes only from a consumed durable permit; callers cannot supply a URL,
 * method, path, redirect, body, hostname, or arbitrary port.
 */
import { canonicalizeIp, isPrivateOrLocal } from "./check.js";
import {
  DISCOVERY_PROFILES,
  SERVICES,
  probeService,
  resolvePort,
} from "./services.js";

const HEADER_CAP = 16 * 1024;
const BODY_CAP = 32 * 1024;
const USER_AGENT = "LeakyCompute-SafeProbe/3.0 (+https://leakycompute.mahdihedhli.com/scanning)";

function timeoutError(stage) {
  const error = new Error(`${stage}_timeout`);
  error.name = "ProbeTimeoutError";
  return error;
}

async function withDeadline(promise, ms, stage) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(timeoutError(stage)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function concat(chunks, size) {
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    const take = Math.min(chunk.length, size - offset);
    if (take <= 0) break;
    out.set(chunk.subarray(0, take), offset);
    offset += take;
  }
  return out;
}

function decodeChunked(bytes, cap) {
  const text = new TextDecoder("latin1").decode(bytes);
  let offset = 0;
  const pieces = [];
  let total = 0;
  while (offset < text.length && total < cap) {
    const lineEnd = text.indexOf("\r\n", offset);
    if (lineEnd < 0) throw new Error("malformed_chunk_size");
    const token = text.slice(offset, lineEnd).split(";", 1)[0].trim();
    if (!/^[0-9a-f]+$/i.test(token)) throw new Error("malformed_chunk_size");
    const size = Number.parseInt(token, 16);
    offset = lineEnd + 2;
    if (size === 0) break;
    if (offset + size + 2 > bytes.length) throw new Error("truncated_chunk");
    const take = Math.min(size, cap - total);
    pieces.push(bytes.subarray(offset, offset + take));
    total += take;
    offset += size;
    if (text.slice(offset, offset + 2) !== "\r\n") throw new Error("malformed_chunk_end");
    offset += 2;
  }
  return concat(pieces, total);
}

function parseResponse(bytes, maxBytes) {
  const marker = new TextEncoder().encode("\r\n\r\n");
  let headerEnd = -1;
  outer: for (let i = 0; i <= Math.min(bytes.length - marker.length, HEADER_CAP); i++) {
    for (let j = 0; j < marker.length; j++) {
      if (bytes[i + j] !== marker[j]) continue outer;
    }
    headerEnd = i;
    break;
  }
  if (headerEnd < 0) throw new Error("invalid_http_headers");

  const head = new TextDecoder("latin1").decode(bytes.subarray(0, headerEnd));
  const lines = head.split("\r\n");
  const statusMatch = /^HTTP\/1\.[01]\s+(\d{3})(?:\s|$)/.exec(lines.shift() || "");
  if (!statusMatch) throw new Error("invalid_http_status");
  const headers = new Map();
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon <= 0) throw new Error("invalid_http_header");
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!headers.has(name)) headers.set(name, value);
  }
  let body = bytes.subarray(headerEnd + 4);
  if (/\bchunked\b/i.test(headers.get("transfer-encoding") || "")) {
    body = decodeChunked(body, maxBytes);
  } else if (body.length > maxBytes) {
    body = body.subarray(0, maxBytes);
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(body);
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return {
    status: Number(statusMatch[1]),
    location: headers.get("location") || "",
    contentType: headers.get("content-type") || "",
    text,
    json: parsed,
  };
}

function platformSocketFailure(error) {
  return /disallowed|tcp loop|cloudflare ip|request failed|not implemented|unsupported/i.test(
    String(error?.message || error)
  );
}

function hostHeader(ip, port) {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function reviewedPaths(service) {
  const paths = new Set();
  if (Object.hasOwn(SERVICES, service)) {
    const profile = SERVICES[service];
    for (const step of profile.confirm) paths.add(step.path);
    paths.add(profile.exposure.path);
  }
  const profile = DISCOVERY_PROFILES[service];
  if (profile) paths.add(profile.path);
  return paths;
}

/** One bounded HTTP GET to one already-authorized address. */
export async function socketGet(
  { ip, port, path, service, connectHostname = null },
  { timeoutMs = 2500, maxBytes = BODY_CAP, connectImpl } = {}
) {
  const canonical = canonicalizeIp(ip);
  const resolved = resolvePort(service, port);
  if (!canonical || canonical !== ip || isPrivateOrLocal(canonical)) {
    return { ok: false, status: 0, error: "target_not_public_unicast", error_class: "authorization_error" };
  }
  if (!resolved.ok || resolved.port !== Number(port)) {
    return { ok: false, status: 0, error: resolved.error || "port_not_allowed", error_class: "authorization_error" };
  }
  if (!reviewedPaths(service).has(path)) {
    return { ok: false, status: 0, error: "path_not_allowed", error_class: "authorization_error" };
  }
  const canaryHostname = String(connectHostname || "").trim().toLowerCase();
  if (
    canaryHostname &&
    (service !== "owned_canary" ||
      !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(canaryHostname) ||
      canaryHostname.includes(".."))
  ) {
    return { ok: false, status: 0, error: "canary_hostname_not_allowed", error_class: "authorization_error" };
  }

  const started = Date.now();
  let socket;
  try {
    const connect = connectImpl || (await import("cloudflare:sockets")).connect;
    socket = connect(
      { hostname: canaryHostname || canonical, port: Number(port) },
      { secureTransport: canaryHostname ? "on" : "off", allowHalfOpen: false }
    );
    await withDeadline(socket.opened, timeoutMs, "connect");

    const request = new TextEncoder().encode(
      `GET ${path} HTTP/1.0\r\n` +
      `Host: ${hostHeader(canaryHostname || canonical, port)}\r\n` +
      "Accept: application/json, text/html;q=0.8, */*;q=0.5\r\n" +
      `User-Agent: ${USER_AGENT}\r\n` +
      "Connection: close\r\n\r\n"
    );
    const writer = socket.writable.getWriter();
    await withDeadline(writer.write(request), timeoutMs, "write");
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const chunks = [];
    let received = 0;
    const totalDeadline = Date.now() + timeoutMs;
    while (received < HEADER_CAP + maxBytes) {
      const remaining = totalDeadline - Date.now();
      if (remaining <= 0) throw timeoutError("read");
      const { done, value } = await withDeadline(reader.read(), remaining, "read");
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error("invalid_socket_chunk");
      const take = Math.min(value.length, HEADER_CAP + maxBytes - received);
      chunks.push(value.subarray(0, take));
      received += take;
      if (take < value.length) break;
    }
    try { await reader.cancel(); } catch { /* already closed */ }
    const parsed = parseResponse(concat(chunks, received), Math.min(maxBytes, BODY_CAP));
    return {
      ok: true,
      ...parsed,
      latency_ms: Date.now() - started,
      error: null,
      error_class: null,
    };
  } catch (error) {
    const timedOut = error?.name === "ProbeTimeoutError";
    return {
      ok: false,
      status: 0,
      location: "",
      contentType: "",
      text: "",
      json: null,
      latency_ms: Date.now() - started,
      error: timedOut ? String(error.message) : "socket_error",
      error_class: platformSocketFailure(error) ? "platform_error" : "target_error",
    };
  } finally {
    if (socket) {
      try { await socket.close(); } catch { /* best effort */ }
    }
  }
}

/** Transport adapter for the existing tier-1 fingerprint engine. */
export function pinnedTransport(permit, { connectImpl } = {}) {
  return async (url, options = {}) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return { ok: false, status: 0, error: "invalid_internal_url", error_class: "platform_error" };
    }
    const urlIp = canonicalizeIp(parsed.hostname);
    const urlPort = Number(parsed.port);
    if (urlIp !== permit.ip || urlPort !== Number(permit.port) || parsed.search || parsed.hash) {
      return { ok: false, status: 0, error: "permit_destination_mismatch", error_class: "authorization_error" };
    }
    return socketGet(
      { ip: permit.ip, port: permit.port, path: parsed.pathname, service: permit.service },
      { ...options, connectImpl }
    );
  };
}

export async function runHostedPermit(permit, { timeoutMs = 2500, connectImpl } = {}) {
  if (!Object.hasOwn(SERVICES, permit.service)) {
    return { ok: false, error: "hosted_service_not_supported", error_class: "authorization_error" };
  }
  const result = await probeService(permit.ip, permit.service, permit.port, {
    timeoutMs,
    transport: pinnedTransport(permit, { connectImpl }),
  });
  return { ok: true, result };
}

export async function runDiscoveryPermit(permit, { timeoutMs = 2500, connectImpl } = {}) {
  const profile = DISCOVERY_PROFILES[permit.service];
  if (!profile) {
    return { ok: false, error: "unknown_service", error_class: "authorization_error" };
  }
  const response = await socketGet(
    {
      ip: permit.ip,
      port: permit.port,
      path: profile.path,
      service: permit.service,
      connectHostname: permit.service === "owned_canary" ? permit.canary_hostname : null,
    },
    { timeoutMs, connectImpl }
  );
  if (!response.ok) {
    return {
      ok: true,
      result: {
        service: permit.service,
        port: permit.port,
        status: 0,
        exposed: false,
        answered: false,
        error: response.error,
        error_class: response.error_class,
      },
    };
  }
  const exposed = response.status === 200 && validatesDiscoveryProfile(permit.service, response);
  const modelRows = Array.isArray(response.json?.models)
    ? response.json.models
    : Array.isArray(response.json?.data) ? response.json.data : [];
  return {
    ok: true,
    result: {
      service: permit.service,
      port: permit.port,
      status: response.status,
      exposed,
      answered: true,
      authenticated: response.status === 401 || response.status === 403 || response.status === 407,
      version: exposed && response.json && typeof response.json === "object"
        ? ["version", "server_version", "ray_version", "app_version"]
            .map((key) => response.json[key])
            .find((value) => typeof value === "string")?.slice(0, 64) || null
        : null,
      models: exposed
        ? modelRows.slice(0, 25).map((model) => ({
            name: String(model?.name || model?.model || model?.id || "unknown").slice(0, 128),
            size: Number.isFinite(model?.size) ? model.size : null,
          }))
        : [],
      canary_marker: permit.service === "owned_canary" && response.json?.leakycompute_canary === "owned"
        ? "owned"
        : null,
      error: null,
      error_class: null,
    },
  };
}

function validatesDiscoveryProfile(service, response) {
  const json = response.json;
  const text = String(response.text || "").slice(0, 4096).toLowerCase();
  switch (service) {
    case "owned_canary": return json?.leakycompute_canary === "owned";
    case "ollama": return Array.isArray(json?.models);
    case "ray": return !!json && typeof json === "object" &&
      [json.ray_version, json.version].some((value) => typeof value === "string");
    case "jupyter": return /jupyter|notebook|jupyterlab/.test(text);
    case "open_webui": return !!json && typeof json === "object" &&
      ["name", "version", "features", "default_models"].some((key) => Object.hasOwn(json, key));
    case "localai":
    case "vllm":
    case "openai_compat_8000":
    case "openai_compat_8080": return Array.isArray(json?.data);
    case "litellm": return !!json && typeof json === "object" &&
      ["status", "healthy_endpoints", "healthy_count"].some((key) => Object.hasOwn(json, key));
    case "comfyui": return !!json && typeof json === "object" &&
      (Object.hasOwn(json, "system") || Object.hasOwn(json, "devices"));
    case "gradio": return !!json && typeof json === "object" &&
      (Array.isArray(json.components) || typeof json.version === "string");
    case "mlflow": return /mlflow/.test(text);
    case "triton": return !!json && typeof json === "object" &&
      typeof json.name === "string" && Array.isArray(json.extensions);
    case "tensorboard": return !!json && typeof json === "object" &&
      Object.keys(json).some((key) => /scalars|graphs|images|histograms/.test(key));
    default: return false;
  }
}

export function completionOutcome(results) {
  const list = Array.isArray(results) ? results : [results].filter(Boolean);
  if (list.some((result) => result?.error_class === "platform_error" || result?.error_class === "authorization_error")) {
    return "platform_error";
  }
  if (list.some((result) => result?.error_class === "target_error")) return "target_error";
  if (list.some((result) => result?.exposed)) return "exposed";
  return "not_observed";
}
