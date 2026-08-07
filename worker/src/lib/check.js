/**
 * Target validation for the safe self-check.
 *
 * The probe engine itself lives in ./services.js — this module is only
 * responsible for deciding what we are allowed to point it at.
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

// Port validation now lives in ./services.js (resolvePort): ports are
// validated against the specific service's known-port list rather than the
// full 1-65535 range, so this endpoint cannot be used as a port prober.
