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
    "Access-Control-Allow-Headers":
      "Content-Type, cf-access-jwt-assertion, Cf-Access-Jwt-Assertion, Authorization, X-Admin-Token",
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

export function noContent(request, env) {
  return new Response(null, { status: 204, headers: corsHeaders(request, env) });
}
