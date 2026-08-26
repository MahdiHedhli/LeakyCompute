/**
 * Access-authenticated bridge from the lab to the Worker.
 *
 * The gap this closes: Cloudflare Access protects the Pages project and sets
 * CF_Authorization on leakycompute-lab.pages.dev. The API lives on
 * api.leakycompute.mahdihedhli.com — a different hostname — so the
 * browser never sends that cookie there, and a static Pages site has no server
 * to inject the header instead. Every lab request therefore arrived at the
 * Worker with no identity and came back 401. access.js has carried a comment
 * about this since it was written; this is that comment resolved.
 *
 * A Pages Function *does* receive Cf-Access-Jwt-Assertion, because Access sits
 * in front of it. So the browser calls same-origin, and this forwards the
 * assertion on. The Worker's verification is unchanged: it still validates the
 * JWT against ACCESS_TEAM_DOMAIN and ACCESS_AUD, and still requires an allowlist
 * entry. This adds a hop, not a bypass.
 *
 * On the word "proxy": I-20 forbids proxying user traffic through *third-party
 * hosts* — the behaviour that defined STOLEN COMPUTE. This forwards a request
 * to our own API, carrying our own user's identity. Different thing entirely,
 * and worth stating rather than leaving to inference.
 *
 * Scope is deliberately narrow. The route only matches /v1/research/*, so it
 * cannot reach /v1/admin/*, and it never carries an admin token. If it were a
 * general forwarder it would be a way around the admin gate.
 */

const UPSTREAM = "https://api.leakycompute.mahdihedhli.com";

// Only these ever leave here. An allowlist rather than a denylist: a header we
// forget to strip is a header the upstream might trust.
const FORWARD_HEADERS = [
  "cf-access-jwt-assertion",
  "accept",
  "content-type",
];

const BRIDGE_ROUTES = new Set([
  "me",
  "catalog",
  "lab/catalog",
  "lab/map",
  "lab/validation",
  "lab/host",
]);

export async function onRequest(context) {
  const { request, params } = context;

  // Read-only surface. The lab never writes, so anything else is a mistake or
  // an attempt.
  if (request.method !== "GET" && request.method !== "OPTIONS") {
    return json({ error: "method_not_allowed" }, 405);
  }
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!jwt) {
    // Reaching here without an assertion means Access is not actually in front
    // of this deployment. Fail loudly: the alternative is forwarding an
    // unauthenticated request and letting the Worker decide, which would make a
    // misconfigured gate look like an ordinary 401.
    return json(
      {
        error: "no_access_assertion",
        message:
          "This request did not carry a Cloudflare Access assertion, which means " +
          "Access is not protecting this deployment. Refusing to forward.",
      },
      403
    );
  }

  const parts = Array.isArray(params.path) ? params.path : [params.path || ""];
  let sub;
  try {
    sub = parts.map((p) => decodeURIComponent(String(p))).join("/");
  } catch {
    return json({ error: "invalid_path" }, 400);
  }
  // URL construction normalizes ../ segments. A fixed prefix is not a gate if
  // untrusted segments can normalize out of it, so bridge only exact lab routes.
  if (!BRIDGE_ROUTES.has(sub)) {
    return json({ error: "route_not_allowed" }, 404);
  }

  // Access returns a browser to the exact URL that started authentication. If
  // that URL was the identity endpoint, a top-level navigation would otherwise
  // end on raw JSON (and some browser extensions block it outright). Send only
  // document navigations back to the lab shell. The shell's application/json
  // fetch still reaches /me normally, so this cannot weaken the identity gate.
  const acceptsHtml = /(^|,)\s*text\/html(?:\s*;|\s*(?:,|$))/i.test(
    request.headers.get("Accept") || ""
  );
  if (
    sub === "me" &&
    (request.headers.get("Sec-Fetch-Mode") === "navigate" || acceptsHtml)
  ) {
    const location = new URL("/", request.url);
    return new Response(null, {
      status: 302,
      headers: {
        Location: location.toString(),
        "Cache-Control": "no-store",
      },
    });
  }

  const url = new URL(request.url);
  const target = `${UPSTREAM}/v1/research/${sub}${url.search}`;

  const headers = new Headers();
  for (const name of FORWARD_HEADERS) {
    const v = request.headers.get(name);
    if (v) headers.set(name, v);
  }

  let upstream;
  try {
    upstream = await fetch(target, {
      method: "GET",
      headers,
      redirect: "manual",
    });
  } catch (err) {
    const requestId = crypto.randomUUID();
    console.error("research bridge upstream failed", {
      request_id: requestId,
      error: String(err?.message || err),
    });
    return json({ error: "upstream_unreachable", request_id: requestId }, 502);
  }

  // Pass the body through untouched — the Worker owns what a researcher may
  // see (I-14), and re-deciding that here would mean two places to get it wrong.
  const out = new Headers(upstream.headers);
  out.delete("set-cookie");
  // Same-origin now, so the Worker's CORS headers are meaningless here and
  // stale ones only confuse debugging.
  out.delete("access-control-allow-origin");
  out.delete("access-control-allow-credentials");
  out.set("Cache-Control", "no-store");

  return new Response(upstream.body, { status: upstream.status, headers: out });
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
