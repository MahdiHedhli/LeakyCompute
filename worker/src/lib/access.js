/**
 * Cloudflare Access JWT verification (lab routes).
 * Dev bypass: ENVIRONMENT=development and header X-Dev-GitHub-Login.
 *
 * Production: set ACCESS_TEAM_DOMAIN + ACCESS_AUD (Application AUD tag).
 * GitHub IdP: identity candidates come only from the signed Access assertion.
 * Caller-supplied identity headers are never trusted in production.
 */

const certCache = { keys: null, fetchedAt: 0, team: null };

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
  if (
    certCache.keys &&
    certCache.team === teamDomain &&
    now - certCache.fetchedAt < 60 * 60 * 1000
  ) {
    return certCache.keys;
  }
  const url = `https://${teamDomain}/cdn-cgi/access/certs`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error("access_certs_fetch_failed");
  const data = await resp.json();
  certCache.keys = data.keys || [];
  certCache.fetchedAt = now;
  certCache.team = teamDomain;
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
  if (header.alg !== "RS256" || (header.typ && header.typ !== "JWT")) {
    return { ok: false, error: "jwt_header_rejected" };
  }
  if (payload.aud !== aud && !(Array.isArray(payload.aud) && payload.aud.includes(aud))) {
    return { ok: false, error: "aud_mismatch" };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const issuer = `https://${String(team).replace(/^https?:\/\//, "").replace(/\/$/, "")}`;
  if (payload.iss !== issuer) return { ok: false, error: "iss_mismatch" };
  if (payload.type !== "app") return { ok: false, error: "token_type_rejected" };
  if (!Number.isFinite(payload.exp) || payload.exp <= nowSec) {
    return { ok: false, error: "jwt_expired" };
  }
  if (payload.nbf != null && (!Number.isFinite(payload.nbf) || payload.nbf > nowSec)) {
    return { ok: false, error: "jwt_not_yet_valid" };
  }
  if (payload.iat != null && (!Number.isFinite(payload.iat) || payload.iat > nowSec + 60)) {
    return { ok: false, error: "jwt_issued_in_future" };
  }
  const keys = await getAccessCerts(team);
  const jwk = keys.find((k) => k.kid === header.kid);
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

  let verified;
  try {
    verified = await verifyAccessJwt(jwt, env);
  } catch {
    return null;
  }
  if (!verified.ok) return null;

  const p = verified.payload || {};
  const email = p.email || null;

  // Authorization uses only exact, IdP-verified identities. Display-oriented
  // claims such as nickname/preferred_username are mutable and non-unique; an
  // email local-part can be chosen to equal somebody else's GitHub handle.
  // Approval therefore stores the exact Access sign-in email as an alias.
  const candidates = [];
  const push = (v) => {
    if (v == null) return;
    const s = String(v).trim().toLowerCase().replace(/^@/, "");
    if (s && !candidates.includes(s)) candidates.push(s);
  };

  push(email);

  if (!candidates.length) return null;

  return {
    // The first candidate is what we display; every candidate is what we match.
    login: candidates[0],
    candidates,
    email,
    dev: false,
    payload: p,
  };
}
