/**
 * Domain-ready CORS: configure ALLOWED_ORIGINS as comma-separated list.
 * When you buy a domain, add https://lab.example.com and https://example.com.
 */
export function parseOrigins(env) {
  const raw = env.ALLOWED_ORIGINS || "";
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = parseOrigins(env);
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    // X-Dev-GitHub-Login is the local-dev identity header (access.js honours it
    // only when ENVIRONMENT=development, so allowing it here is inert in
    // production). Without it the preflight passes and the real request is
    // blocked, which is why the lab's dev path had never rendered in a browser:
    // curl ignores CORS, so every endpoint test passed while the UI could not
    // load at all.
    "Access-Control-Allow-Headers":
      "Content-Type, cf-access-jwt-assertion, Cf-Access-Jwt-Assertion, Authorization, X-Admin-Token, X-Dev-GitHub-Login",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  if (origin && allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  } else if (allowed.includes("*")) {
    headers["Access-Control-Allow-Origin"] = "*";
  }
  return headers;
}

export function json(data, status, request, env, extra = {}) {
  return new Response(JSON.stringify(data, null, 0), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(request, env),
      ...extra,
    },
  });
}

/**
 * Credential-free public JSON has one representation at the edge. Using the
 * request Origin here would create an attacker-controlled cache variant for
 * every header value and turn /v1/stats back into a KV-read amplifier.
 */
export function publicJson(data, status, extra = {}) {
  return new Response(JSON.stringify(data, null, 0), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "X-Content-Type-Options": "nosniff",
      ...extra,
    },
  });
}

export function noContent(request, env) {
  return new Response(null, {
    status: 204,
    headers: {
      "Cache-Control": "no-store",
      ...corsHeaders(request, env),
    },
  });
}
