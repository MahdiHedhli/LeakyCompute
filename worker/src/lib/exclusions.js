/**
 * Scanning exclusion list — I-25.
 *
 * An operator who asks to be left alone is honoured before any request is
 * emitted, not after review. This module is the mechanism behind that promise.
 *
 * Two consumers:
 *   - the off-Worker discovery runner, which fetches the list and filters
 *     candidates before probing (and refuses to run if it cannot fetch it);
 *   - /v1/check, which refuses an override target inside excluded space.
 *
 * Design bias: every ambiguous case resolves toward *not* probing. A malformed
 * entry is rejected at ingest rather than stored as something that silently
 * matches nothing, and a match failure that throws is treated as a match.
 */

const KEY = "exclusions:v1";

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;

/* ------------------------------------------------------------------ */
/* Address arithmetic                                                  */
/* ------------------------------------------------------------------ */

function ipv4ToInt(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

/** Expand an IPv6 address (including :: compression) to a 128-bit BigInt. */
function ipv6ToBigInt(ip) {
  let s = String(ip).toLowerCase().replace(/^\[|\]$/g, "");
  if (s.includes(".")) {
    // IPv4-mapped tail, e.g. ::ffff:192.0.2.1
    const at = s.lastIndexOf(":");
    const v4 = ipv4ToInt(s.slice(at + 1));
    if (v4 == null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    s = `${s.slice(0, at + 1)}${hi}:${lo}`;
  }
  const dbl = s.split("::");
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(":") : [];
  const tail = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (dbl.length === 1) {
    if (head.length !== 8) return null;
  } else if (fill < 0) {
    return null;
  }
  const groups =
    dbl.length === 2 ? [...head, ...Array(fill).fill("0"), ...tail] : head;
  let out = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out = (out << 16n) | BigInt(parseInt(g, 16));
  }
  return out;
}

function isIpv6(s) {
  return typeof s === "string" && s.includes(":");
}

/* ------------------------------------------------------------------ */
/* Entry parsing                                                       */
/* ------------------------------------------------------------------ */

/**
 * Parse one operator-supplied line into a normalised entry.
 * Returns null for anything we cannot represent exactly — the caller reports
 * it back rather than storing a rule that would never fire.
 */
export function parseExclusionEntry(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (!s || s.startsWith("#")) return null;

  // ASN — "AS64496", "as64496", "64496"
  const asn = /^(?:as)?(\d{1,10})$/.exec(s);
  if (asn) {
    const n = Number(asn[1]);
    if (!Number.isInteger(n) || n < 0 || n > 4294967295) return null;
    return { type: "asn", value: `AS${n}` };
  }

  // CIDR
  if (s.includes("/")) {
    const [addr, bitsRaw] = s.split("/");
    const bits = Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0) return null;
    if (IPV4.test(addr)) {
      if (bits > 32 || ipv4ToInt(addr) == null) return null;
      return { type: "cidr4", value: `${addr}/${bits}` };
    }
    if (isIpv6(addr)) {
      if (bits > 128 || ipv6ToBigInt(addr) == null) return null;
      return { type: "cidr6", value: `${addr}/${bits}` };
    }
    return null;
  }

  if (IPV4.test(s)) return { type: "cidr4", value: `${s}/32` };
  if (isIpv6(s) && ipv6ToBigInt(s) != null) return { type: "cidr6", value: `${s}/128` };

  return null;
}

/* ------------------------------------------------------------------ */
/* Matching                                                            */
/* ------------------------------------------------------------------ */

function cidr4Match(entryValue, ip) {
  const [net, bitsRaw] = entryValue.split("/");
  const bits = Number(bitsRaw);
  const a = ipv4ToInt(net);
  const b = ipv4ToInt(ip);
  if (a == null || b == null) return false;
  if (bits === 0) return true;
  const mask = bits >= 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function cidr6Match(entryValue, ip) {
  const [net, bitsRaw] = entryValue.split("/");
  const bits = BigInt(Number(bitsRaw));
  const a = ipv6ToBigInt(net);
  const b = ipv6ToBigInt(ip);
  if (a == null || b == null) return false;
  if (bits === 0n) return true;
  const shift = 128n - bits;
  return a >> shift === b >> shift;
}

function normAsn(v) {
  const m = /^(?:as)?(\d{1,10})$/.exec(String(v || "").trim().toLowerCase());
  return m ? `AS${Number(m[1])}` : null;
}

/**
 * Does this target fall inside any active exclusion?
 * Throwing is treated as a match — we would rather skip a host than probe one
 * we could not prove was permitted.
 */
export function isExcluded(entries, { ip, asn } = {}) {
  if (!Array.isArray(entries) || !entries.length) return false;
  const targetAsn = normAsn(asn);
  const v6 = isIpv6(ip);
  for (const e of entries) {
    if (!e || e.active === false) continue;
    try {
      if (e.type === "asn") {
        if (targetAsn && e.value === targetAsn) return true;
        continue;
      }
      if (!ip) continue;
      if (e.type === "cidr4" && !v6 && cidr4Match(e.value, ip)) return true;
      if (e.type === "cidr6" && v6 && cidr6Match(e.value, ip)) return true;
    } catch {
      // Unparseable rule against this target: fail toward exclusion.
      return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

export async function loadExclusions(env) {
  if (!env.KV) return [];
  const rows = await env.KV.get(KEY, "json");
  return Array.isArray(rows) ? rows : [];
}

/**
 * Auto-honour bound.
 *
 * Honour-on-receipt has one abuse case worth closing: anyone can open an issue,
 * so anyone could submit 0.0.0.0/0 and switch the project off. Exclusions this
 * broad are still accepted — just not automatically. They are held for a
 * maintainer, who applies the approval label to re-run with allowBroad.
 *
 * The bound is deliberately generous. A /16 covers any plausible single
 * operator, and a whole-ASN request — the normal shape for a hosting provider
 * asking on behalf of its customers — is always auto-honoured regardless of how
 * much address space that ASN holds.
 */
const AUTO_BITS = { cidr4: 16, cidr6: 32 };

export function isBroad(entry) {
  const min = AUTO_BITS[entry.type];
  if (min == null) return false; // ASN: always auto-honoured
  return Number(entry.value.split("/")[1]) < min;
}

/**
 * Add entries. Exclusions never expire and are never removed by this path —
 * withdrawing one is a deliberate manual act, so an accidental replay of a
 * removal request can only ever widen the list.
 */
export async function addExclusions(env, lines, meta = {}) {
  const existing = await loadExclusions(env);
  const result = planExclusions(existing, lines, meta);
  if (result.accepted.length) {
    await storeExclusions(env, [...existing, ...result.accepted]);
  }
  return result;
}

/** Pure planning step so the Durable Object can activate rules before KV. */
export function planExclusions(existing, lines, meta = {}) {
  const seen = new Set(existing.map((e) => `${e.type}:${e.value}`));
  const accepted = [];
  const rejected = [];
  const held = [];

  for (const line of lines || []) {
    const parsed = parseExclusionEntry(line);
    if (!parsed) {
      rejected.push({ input: String(line).slice(0, 64), reason: "unparseable" });
      continue;
    }
    const k = `${parsed.type}:${parsed.value}`;
    if (seen.has(k)) continue;
    if (isBroad(parsed) && !meta.allowBroad) {
      held.push({ input: parsed.value, reason: "broader_than_auto_honour_bound" });
      continue;
    }
    seen.add(k);
    accepted.push({
      ...parsed,
      active: true,
      issue_number: meta.issue_number ?? null,
      requested_at: new Date().toISOString(),
      source: meta.source || "removal-request",
      broad: isBroad(parsed) || undefined,
    });
  }

  return { accepted, rejected, held, total: existing.length + accepted.length };
}

/** KV is a compatibility mirror; it is never the packet-emission authority. */
export async function storeExclusions(env, entries) {
  if (!env.KV || typeof env.KV.put !== "function") {
    throw new Error("exclusion_kv_unavailable");
  }
  await env.KV.put(KEY, JSON.stringify(entries));
}
