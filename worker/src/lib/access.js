/**
 * Cloudflare Access JWT verification (lab routes).
 * Dev bypass: ENVIRONMENT=development and header X-Dev-GitHub-Login.
 *
 * Production: set ACCESS_TEAM_DOMAIN + ACCESS_AUD (Application AUD tag).
 * GitHub IdP: we prefer custom claim / email local-part; issue approval stores github login.
 * Client may also send X-GitHub-Login when it matches JWT email/name (checked against allowlist only after JWT ok).
 */

const certCache = { keys: null, fetchedAt: 0 };

function b64urlToBytes(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function decodeJwtPart(part) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
}

async function getAccessCerts(teamDomain) {
  const now = Date.now();
  if (certCache.keys && now - certCache.fetchedAt < 60 * 60 * 1000) {
    return certCache.keys;
  }
  const url = `https://${teamDomain}/cdn-cgi/access/certs`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error("access_certs_fetch_failed");
  const data = await resp.json();
  certCache.keys = data.keys || [];
  certCache.fetchedAt = now;
  return certCache.keys;
}

async function importJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function verifyAccessJwt(token, env) {
  const team = env.ACCESS_TEAM_DOMAIN;
  const aud = env.ACCESS_AUD;
  if (!team || !aud) {
    return { ok: false, error: "access_not_configured" };
  }
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, error: "malformed_jwt" };
  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  if (payload.aud !== aud && !(Array.isArray(payload.aud) && payload.aud.includes(aud))) {
    return { ok: false, error: "aud_mismatch" };
  }
  if (payload.exp && payload.exp * 1000 < Date.now()) {
    return { ok: false, error: "jwt_expired" };
  }
  const keys = await getAccessCerts(team);
  const jwk = keys.find((k) => k.kid === header.kid) || keys[0];
  if (!jwk) return { ok: false, error: "no_signing_key" };
  const key = await importJwk(jwk);
  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const sig = b64urlToBytes(parts[2]);
  const valid = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, data);
  if (!valid) return { ok: false, error: "bad_signature" };
  return { ok: true, payload };
}

/**
 * Resolve researcher identity for lab routes.
 * Returns { login, email, dev } or null.
 */
export async function resolveResearcher(request, env) {
  // Dev bypass for local wrangler
  if ((env.ENVIRONMENT || "") === "development") {
    const dev = request.headers.get("X-Dev-GitHub-Login");
    if (dev) {
      return {
        login: dev.toLowerCase().replace(/^@/, ""),
        email: null,
        dev: true,
      };
    }
  }

  const jwt =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    request.headers.get("cf-access-jwt-assertion");

  if (!jwt) {
    // When Access sits in front of Pages only, browser calls to workers.dev
    // may not auto-send the JWT cross-origin. Support Access service token later.
    // For same-zone custom domain, cookie/JWT can be configured.
    return null;
  }

  const verified = await verifyAccessJwt(jwt, env);
  if (!verified.ok) return null;

  const p = verified.payload || {};
  const email = p.email || null;
  // Prefer explicit claim if present; else header asserted login checked against allowlist only
  const claimed =
    p.github_login ||
    p.login ||
    request.headers.get("X-GitHub-Login") ||
    (email ? email.split("@")[0] : null);

  if (!claimed) return null;
  return {
    login: String(claimed).toLowerCase().replace(/^@/, ""),
    email,
    dev: false,
    payload: p,
  };
}
