/**
 * Target validation for the safe self-check.
 *
 * The probe engine itself lives in ./services.js — this module is only
 * responsible for deciding what we are allowed to point it at.
 * Never sends path-traversal, pull, or generate payloads.
 *
 * Public overrides deliberately accept IP literals only. Resolving a caller-
 * supplied hostname and then fetching the hostname again creates a DNS-
 * rebinding window, and checking exclusions before resolution lets a hostname
 * bypass an excluded IP/CIDR. Pinning a resolved address would change Host
 * routing semantics and add a trusted resolver dependency, so the fail-closed
 * boundary is simpler: use a public address here, or the local CLI for names.
 */

function parseIpv4(text) {
  if (typeof text !== "string") return null;
  const parts = text.split(".");
  if (parts.length !== 4) return null;

  const bytes = [];
  for (const part of parts) {
    // Reject ambiguous leading-zero forms. URL parsers have historically
    // interpreted these as octal, which can turn an apparently public address
    // into loopback or private space after validation.
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value > 255) return null;
    bytes.push(value);
  }

  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return { bytes, value };
}

function parseIpv6(text) {
  if (typeof text !== "string" || !text || text.includes("%")) return null;
  let source = text.toLowerCase();

  // Convert an embedded dotted-quad tail (for example ::ffff:192.0.2.1)
  // into two hextets before applying the normal IPv6 parser.
  if (source.includes(".")) {
    const colon = source.lastIndexOf(":");
    if (colon < 0) return null;
    const ipv4 = parseIpv4(source.slice(colon + 1));
    if (!ipv4) return null;
    const hi = ((ipv4.bytes[0] << 8) | ipv4.bytes[1]).toString(16);
    const lo = ((ipv4.bytes[2] << 8) | ipv4.bytes[3]).toString(16);
    source = `${source.slice(0, colon)}:${hi}:${lo}`;
  }

  const halves = source.split("::");
  if (halves.length > 2) return null;

  const parseHalf = (half) => {
    if (!half) return [];
    const tokens = half.split(":");
    if (tokens.some((token) => !/^[0-9a-f]{1,4}$/.test(token))) return null;
    return tokens.map((token) => Number.parseInt(token, 16));
  };

  const left = parseHalf(halves[0]);
  const right = halves.length === 2 ? parseHalf(halves[1]) : [];
  if (!left || !right) return null;

  const explicit = left.length + right.length;
  let words;
  if (halves.length === 1) {
    if (explicit !== 8) return null;
    words = left;
  } else {
    // `::` must compress at least one zero word.
    if (explicit >= 8) return null;
    words = [...left, ...Array(8 - explicit).fill(0), ...right];
  }

  let value = 0n;
  for (const word of words) value = (value << 16n) | BigInt(word);
  return { words, value };
}

function inPrefix(value, base, prefixBits, totalBits) {
  const shift = BigInt(totalBits - prefixBits);
  return value >> shift === base >> shift;
}

function canonicalIpv6(words) {
  // A unique storage form prevents equivalent IPv6 spellings from acquiring
  // independent cooldown leases. Display compression is deliberately separate.
  return words.map((word) => word.toString(16).padStart(4, "0")).join(":");
}

export function canonicalizeIp(text) {
  const source = String(text || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  const v4 = parseIpv4(source);
  if (v4) return v4.bytes.join(".");
  const v6 = parseIpv6(source);
  return v6 ? canonicalIpv6(v6.words) : null;
}

/** Conservative neighbourhood bucket used by the durable probe gate. */
export function addressBucket(text) {
  const canonical = canonicalizeIp(text);
  if (!canonical) return null;
  const v4 = parseIpv4(canonical);
  if (v4) return `${v4.bytes[0]}.${v4.bytes[1]}.${v4.bytes[2]}.0/24`;
  const v6 = parseIpv6(canonical);
  return `${v6.words.slice(0, 3).map((word) => word.toString(16)).join(":")}::/48`;
}

const IPV4_SPECIAL = [
  ["0.0.0.0", 8],       // current network / unspecified
  ["10.0.0.0", 8],      // private
  ["100.64.0.0", 10],   // shared address space (CGNAT)
  ["127.0.0.0", 8],     // loopback
  ["169.254.0.0", 16],  // link-local
  ["172.16.0.0", 12],   // private
  ["192.0.0.0", 24],    // IETF protocol assignments
  ["192.0.2.0", 24],    // documentation
  ["192.31.196.0", 24], // AS112 service
  ["192.52.193.0", 24], // AMT
  ["192.88.99.0", 24],  // deprecated 6to4 relay anycast
  ["192.168.0.0", 16],  // private
  ["192.175.48.0", 24], // AS112 direct delegation
  ["198.18.0.0", 15],   // benchmarking
  ["198.51.100.0", 24], // documentation
  ["203.0.113.0", 24],  // documentation
  ["224.0.0.0", 4],     // multicast
  ["240.0.0.0", 4],     // reserved + limited broadcast
].map(([base, bits]) => [parseIpv4(base).value, bits]);

const IPV6_GLOBAL_UNICAST = [parseIpv6("2000::").value, 3];
const IPV6_SPECIAL_INSIDE_GLOBAL = [
  ["2001::", 23],      // IETF protocol assignments
  ["2001:db8::", 32],  // documentation
  ["2002::", 16],      // deprecated 6to4
  ["3fff::", 20],      // documentation
].map(([base, bits]) => [parseIpv6(base).value, bits]);

/**
 * Return true for anything other than an ordinary, publicly routable unicast
 * IP literal. Invalid text and hostnames fail closed.
 */
export function isPrivateOrLocal(ip) {
  const v4 = parseIpv4(ip);
  if (v4) {
    return IPV4_SPECIAL.some(([base, bits]) =>
      inPrefix(v4.value, base, bits, 32)
    );
  }

  const v6 = parseIpv6(ip);
  if (!v6) return true;
  if (!inPrefix(v6.value, IPV6_GLOBAL_UNICAST[0], IPV6_GLOBAL_UNICAST[1], 128)) {
    return true;
  }
  return IPV6_SPECIAL_INSIDE_GLOBAL.some(([base, bits]) =>
    inPrefix(v6.value, base, bits, 128)
  );
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
  // Block URL schemes and userinfo tricks in the host field.
  if (/^[a-z]+:/.test(h) || h.includes("@")) {
    return { ok: false, error: "invalid_target" };
  }

  const canonical = canonicalizeIp(h);
  if (canonical) {
    return { ok: true, host: canonical, kind: "ip" };
  }

  const looksLikeHostname =
    /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(h);
  if (looksLikeHostname) {
    return { ok: false, error: "hostname_target_not_allowed" };
  }
  return { ok: false, error: "invalid_target" };
}

// Port validation lives in ./services.js (resolvePort): ports are validated
// against the specific service's known-port list rather than the full 1-65535
// range, so this endpoint cannot be used as a general-purpose port prober.
