/**
 * I-14 per route: raw addresses exist only behind the admin token or the
 * Access-gated researcher lab, and every gated route refuses an ungated caller.
 *
 * The route inventory below is checked against the router itself, so adding a
 * route without deciding what gates it fails this suite rather than shipping
 * ungated. The lab suite also carries positive controls — the same corpus
 * address the public routes must never contain is asserted *present* on the
 * gated ones, so a leak-detection assertion that silently stopped matching
 * anything would be caught.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import worker from "../src/index.js";
import {
  recordExposedHost,
  recommendDiscoveryCandidates,
} from "../src/lib/discovery.js";
import { LAB_ROUTES } from "../src/lib/lab.js";
import { check, section, finish, makeKV, daysAgo } from "./_harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, "..", "src");

const ADMIN = "test-admin-token";
const NOMINATOR = "test-nominator-token";
const RESEARCHER = "trusted-researcher";

/** Distinctive documentation-range addresses; any appearance is unambiguous. */
const CORPUS_IP = "198.51.100.77";
const CORPUS_IP_2 = "203.0.113.88";
const CLIENT_IP = "198.51.100.99";

const ctx = { waitUntil: (p) => p.catch(() => {}) };

async function seededEnv(overrides = {}) {
  const env = {
    KV: makeKV(),
    // Dev identity bypass; the lab's gate still requires the allowlist entry.
    ENVIRONMENT: "development",
    HOSTED_CHECKS_ENABLED: "true",
    LEGACY_TEST_TRANSPORT: "true",
    ALLOWED_ORIGINS: "https://mahdihedhli.github.io",
    ADMIN_SYNC_TOKEN: ADMIN,
    DISCOVERY_NOMINATOR_TOKEN: NOMINATOR,
    CHECK_TIMEOUT_MS: "200",
    // The lab's corpus cache is module-level, so a suite that builds a fresh
    // env per case would otherwise assert against the previous case's corpus.
    LAB_CACHE_TTL_SEC: "0",
    SNAPSHOT_HOSTS: "19348",
    SNAPSHOT_MODELS: "1000",
    ...overrides,
  };
  await recordExposedHost(env, {
    ip: CORPUS_IP,
    port: 11434,
    stack: "ollama",
    version: "0.1.40",
    country: "Germany",
    country_code: "DE",
    asn: "AS64496",
    source: "shodan:ollama",
  });
  await recordExposedHost(env, {
    ip: CORPUS_IP_2,
    port: 8888,
    stack: "jupyter",
    country_code: "US",
    asn: "AS64497",
    source: "shodan:jupyter",
  });
  await env.KV.put(
    `allowlist:github:${RESEARCHER}`,
    JSON.stringify({ login: RESEARCHER, active: true })
  );
  return env;
}

function req(method, url, { headers = {}, body } = {}) {
  return new Request(`https://api.test${url}`, {
    method,
    headers: {
      Origin: "https://mahdihedhli.github.io",
      "CF-Connecting-IP": CLIENT_IP,
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}

/* ------------------------------------------------------------------ */
/* The inventory. Every route the Worker answers must appear here.     */
/* ------------------------------------------------------------------ */

const PUBLIC_ROUTES = [
  { method: "GET", path: "/" },
  { method: "GET", path: "/v1/health" },
  { method: "GET", path: "/v1/stats" },
  { method: "POST", path: "/v1/check", body: {} },
];

const RESEARCHER_ROUTES = [
  { method: "GET", path: "/v1/research/me" },
  { method: "GET", path: "/v1/research/catalog" },
  { method: "GET", path: "/v1/research/lab/catalog" },
  { method: "GET", path: "/v1/research/lab/map" },
  { method: "GET", path: "/v1/research/lab/validation" },
  { method: "GET", path: `/v1/research/lab/host?ip=${CORPUS_IP}` },
];

const ADMIN_ROUTES = [
  { method: "POST", path: "/v1/admin/allowlist", body: { login: "someone" } },
  { method: "POST", path: "/v1/admin/exclusions", body: { entries: ["203.0.113.0/24"] } },
  { method: "GET", path: "/v1/admin/exclusions" },
  { method: "GET", path: "/v1/admin/discovery/hits" },
  // I-24 re-probe clock. Admin-gated for the same reason as /hits: it is a list
  // of addresses, including hosts that never answered (I-14).
  { method: "GET", path: "/v1/admin/discovery/clock" },
  { method: "POST", path: "/v1/admin/discovery/ingest", body: { results: [] } },
  { method: "POST", path: "/v1/admin/discovery/sweep", body: {} },
  // Recount of published aggregates — admin-gated because it rewrites what the
  // public page reports.
  { method: "POST", path: "/v1/admin/discovery/reconcile", body: {} },
  // Final-verification queue: hosts one day from retention deletion. Admin-gated
  // because it is a list of addresses (I-14), same as /hits and /clock.
  { method: "GET", path: "/v1/admin/discovery/expiring" },
  // Deletion with evidence — the final probe ran and found nothing.
  { method: "POST", path: "/v1/admin/discovery/retire", body: { ips: ["203.0.113.5"] } },
  // Shodan pagination state. No addresses, but it steers what gets probed next,
  // so it is not something an unauthenticated caller may read or move.
  { method: "GET", path: "/v1/admin/discovery/cursors" },
  { method: "POST", path: "/v1/admin/discovery/cursors", body: { lane: "ollama", page: 2 } },
  // Aggregate-only budget state still controls active scheduling and is admin-only.
  { method: "GET", path: "/v1/admin/discovery/budget" },
  // Dark control plane. These routes mutate permission state but cannot emit a
  // target request; they are still admin-only because they carry raw addresses.
  { method: "GET", path: "/v1/admin/control/health" },
  { method: "POST", path: "/v1/admin/control/migrate", body: {} },
  { method: "POST", path: "/v1/admin/control/schema", body: {} },
  { method: "POST", path: "/v1/admin/control/reconcile", body: {} },
  { method: "POST", path: "/v1/admin/control/retention", body: {} },
  { method: "POST", path: "/v1/admin/control/purge", body: {} },
  { method: "GET", path: "/v1/admin/control/hosts" },
  { method: "POST", path: "/v1/admin/control/hosts", body: { records: [] } },
  { method: "GET", path: "/v1/admin/control/attempts" },
  { method: "POST", path: "/v1/admin/control/attempts/import", body: { attempts: [] } },
  { method: "GET", path: "/v1/admin/control/expiring" },
  { method: "POST", path: "/v1/admin/control/retire", body: { ips: [] } },
  { method: "POST", path: "/v1/admin/control/canary", body: {} },
  { method: "POST", path: "/v1/admin/control/exclusions", body: { entries: [] } },
  { method: "GET", path: "/v1/admin/control/aggregates" },
  { method: "POST", path: "/v1/admin/discovery/lease", body: {} },
  { method: "POST", path: "/v1/admin/discovery/permit", body: {} },
  { method: "POST", path: "/v1/admin/discovery/complete", body: {} },
  { method: "POST", path: "/v1/admin/discovery/probe", body: {} },
];

const NOMINATOR_ROUTES = [
  { method: "POST", path: "/v1/nominator/discovery/nominations", body: { nominations: [] } },
  { method: "GET", path: "/v1/nominator/discovery/cursors" },
  { method: "POST", path: "/v1/nominator/discovery/cursors", body: { lane: "ollama", page: 2 } },
];

/* ------------------------------------------------------------------ */
section("[N1] the inventory matches the router (a new route cannot slip past)");

{
  const indexSrc = fs.readFileSync(path.join(SRC, "index.js"), "utf8");
  const routed = new Set();
  for (const m of indexSrc.matchAll(/path === "([^"]+)"/g)) routed.add(m[1]);
  for (const r of LAB_ROUTES) routed.add(r.path);

  const covered = new Set(
    [...PUBLIC_ROUTES, ...RESEARCHER_ROUTES, ...ADMIN_ROUTES, ...NOMINATOR_ROUTES]
      .map((r) => r.path.split("?")[0])
  );

  await check("every path the router matches has a declared gate in this suite", () => {
    const missing = [...routed].filter((p) => !covered.has(p));
    assert.deepEqual(
      missing,
      [],
      `route(s) with no I-14 gating assertion: ${missing.join(", ")}`
    );
  });
}

section("[N4a] every nominator route refuses a caller without its separate token");

for (const route of NOMINATOR_ROUTES) {
  const env = await seededEnv();
  const noToken = await worker.fetch(req(route.method, route.path, { body: route.body }), env, ctx);
  const wrongRole = await worker.fetch(
    req(route.method, route.path, {
      body: route.body,
      headers: { "X-Admin-Token": ADMIN, "X-Nominator-Token": "nope" },
    }),
    env,
    ctx
  );
  await check(`${route.method} ${route.path} without nominator token -> 401`, () => {
    assert.equal(noToken.status, 401);
  });
  await check(`${route.method} ${route.path} rejects discovery-admin role -> 401`, () => {
    assert.equal(wrongRole.status, 401);
  });
}

/* ------------------------------------------------------------------ */
section("[N2] no public route emits a raw address");

/**
 * Any dotted quad that is not one of the strings our own remediation prose
 * legitimately prints (bind-address advice). Catching the general shape, not
 * just the seeded values, is what makes this survive someone adding a new
 * field carrying a different host's address.
 */
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const PROSE_ADDRESSES = new Set(["127.0.0.1", "0.0.0.0"]);

for (const route of PUBLIC_ROUTES) {
  const env = await seededEnv();
  const res = await worker.fetch(req(route.method, route.path, { body: route.body }), env, ctx);
  const text = await res.text();

  await check(`${route.method} ${route.path} answers without auth`, () => {
    assert.ok(res.status < 400, `expected a public 2xx/3xx, got ${res.status}`);
  });

  await check(`${route.method} ${route.path} contains no corpus address`, () => {
    assert.ok(!text.includes(CORPUS_IP), "leaked a corpus host");
    assert.ok(!text.includes(CORPUS_IP_2), "leaked a corpus host");
  });

  await check(`${route.method} ${route.path} never echoes the caller's IP`, () => {
    assert.ok(!text.includes(CLIENT_IP), "echoed CF-Connecting-IP back (I-13)");
  });

  await check(`${route.method} ${route.path} carries no IPv4 literal at all`, () => {
    const found = [...text.matchAll(IPV4)].map((m) => m[0]).filter((v) => !PROSE_ADDRESSES.has(v));
    assert.deepEqual(found, [], `unexpected address(es) in a public payload: ${found.join(", ")}`);
  });
}

{
  // The public stats payload is the one that grew new fields with spec 001.
  const env = await seededEnv();
  const res = await worker.fetch(req("GET", "/v1/stats"), env, ctx);
  const body = await res.json();

  await check("GET /v1/stats reports the three counts separately, never summed", () => {
    assert.equal(body.archive_snapshot.hosts, 19348);
    assert.equal(typeof body.indexed_observed.hosts, "number");
    assert.equal(typeof body.reverified.hosts, "number");
    assert.ok(/never summed/i.test(body.counts_note));
  });

  await check("GET /v1/stats geography is counts only", () => {
    const buckets = [
      ...(body.geography.by_country || []).map((r) => r.country),
      ...(body.geography.by_asn || []).map((r) => r.asn),
      ...(body.geography.by_stack || []).map((r) => r.stack),
    ];
    // Read the field getGeoStats actually emits. This asserted `row.code ??
    // row.key`, neither of which exists on the payload, so it tested the string
    // "undefined" on every iteration and could not have failed. A fresh regex
    // per call, too: IPV4 carries /g, and .test() advances lastIndex between
    // calls, so consecutive matches were being skipped.
    assert.ok(buckets.length > 0, "no aggregate rows to check — the seed is not exercising this");
    for (const bucket of buckets) {
      assert.ok(
        !new RegExp(IPV4.source).test(String(bucket)),
        `aggregate bucket looks like an address: ${bucket}`
      );
    }
    assert.ok(!JSON.stringify(body.geography).includes(CORPUS_IP));
  });
}

/* ------------------------------------------------------------------ */
section("[N3] every researcher route refuses an ungated caller");

for (const route of RESEARCHER_ROUTES) {
  const env = await seededEnv();
  const res = await worker.fetch(req(route.method, route.path), env, ctx);
  const text = await res.text();

  await check(`${route.method} ${route.path} ungated -> 401`, () => {
    assert.equal(res.status, 401, `expected 401, got ${res.status}`);
  });
  await check(`${route.method} ${route.path} ungated leaks no address`, () => {
    assert.ok(!text.includes(CORPUS_IP) && !text.includes(CORPUS_IP_2));
  });
}

for (const route of RESEARCHER_ROUTES) {
  const env = await seededEnv();
  // Identity resolves, but this login was never approved.
  const res = await worker.fetch(
    req(route.method, route.path, { headers: { "X-Dev-GitHub-Login": "random-stranger" } }),
    env,
    ctx
  );
  const text = await res.text();

  await check(`${route.method} ${route.path} authenticated but not allowlisted -> 403`, () => {
    assert.equal(res.status, 403, `expected 403, got ${res.status}`);
  });
  await check(`${route.method} ${route.path} 403 body leaks no address`, () => {
    assert.ok(!text.includes(CORPUS_IP) && !text.includes(CORPUS_IP_2));
  });
}

/* ------------------------------------------------------------------ */
section("[N4] every admin route refuses a caller without the token");

for (const route of ADMIN_ROUTES) {
  const env = await seededEnv();
  const noToken = await worker.fetch(req(route.method, route.path, { body: route.body }), env, ctx);
  const wrongToken = await worker.fetch(
    req(route.method, route.path, { body: route.body, headers: { "X-Admin-Token": "nope" } }),
    env,
    ctx
  );
  const text = await noToken.text();

  await check(`${route.method} ${route.path} without a token -> 401`, () => {
    assert.equal(noToken.status, 401, `expected 401, got ${noToken.status}`);
  });
  await check(`${route.method} ${route.path} with a wrong token -> 401`, () => {
    assert.equal(wrongToken.status, 401, `expected 401, got ${wrongToken.status}`);
  });
  await check(`${route.method} ${route.path} 401 body leaks no address`, () => {
    assert.ok(!text.includes(CORPUS_IP) && !text.includes(CORPUS_IP_2));
  });
}

{
  await check("adaptive discovery sizing preserves the operational reserve", () => {
    assert.equal(recommendDiscoveryCandidates(990, 100), 425);
    assert.equal(recommendDiscoveryCandidates(425, 100), 300);
    assert.equal(recommendDiscoveryCandidates(100, 100), 0);
  });

  const env = await seededEnv({ KV_DAILY_PUT_BUDGET: "990", KV_DISCOVERY_RESERVE: "100" });
  const today = new Date().toISOString().slice(0, 10);
  await env.KV.put(`kv:puts:${today}`, "500");
  const res = await worker.fetch(
    req("GET", "/v1/admin/discovery/budget", { headers: { "X-Admin-Token": ADMIN } }),
    env,
    ctx
  );
  const body = await res.json();
  await check("the authenticated budget route returns aggregate headroom only", () => {
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(body).sort(), [
      "budget", "ok", "recommended_max_candidates", "remaining", "reserve", "reset_at", "used",
    ]);
    assert.equal(body.used, 500);
    assert.equal(body.remaining, 490);
    assert.equal(body.reserve, 100);
    assert.equal(body.recommended_max_candidates, 358);
    assert.match(body.reset_at, /^\d{4}-\d{2}-\d{2}T00:00:00\.000Z$/);
  });
}

{
  // An empty admin token in env must not turn every caller into an admin.
  const env = await seededEnv({ ADMIN_SYNC_TOKEN: "" });
  const res = await worker.fetch(
    req("GET", "/v1/admin/discovery/hits", { headers: { "X-Admin-Token": "" } }),
    env,
    ctx
  );
  await check("an unset admin token does not open the admin routes", () =>
    assert.equal(res.status, 401)
  );
}

/* ------------------------------------------------------------------ */
section("[N5] positive controls: the gated routes really do hold addresses");

{
  const env = await seededEnv();
  const res = await worker.fetch(
    req("GET", "/v1/admin/discovery/hits", { headers: { "X-Admin-Token": ADMIN } }),
    env,
    ctx
  );
  const text = await res.text();
  await check("the admin hit store returns raw addresses (so the leak check is live)", () => {
    assert.equal(res.status, 200);
    assert.ok(text.includes(CORPUS_IP), "expected the seeded address behind the admin token");
  });
  await check("the admin hit store serialises no model list or page body (I-26)", () => {
    const body = JSON.parse(text);
    for (const hit of body.hits) {
      for (const banned of ["models", "vulns", "city", "org", "product", "times_seen"]) {
        assert.ok(!(banned in hit), `hit still serialises '${banned}'`);
      }
    }
  });
}

for (const route of RESEARCHER_ROUTES) {
  const env = await seededEnv();
  const res = await worker.fetch(
    req(route.method, route.path, { headers: { "X-Dev-GitHub-Login": RESEARCHER } }),
    env,
    ctx
  );
  await check(`${route.method} ${route.path} allowlisted -> 200`, () => {
    assert.equal(res.status, 200, `expected 200, got ${res.status}`);
  });
}

{
  const env = await seededEnv();
  const res = await worker.fetch(
    req("GET", "/v1/research/lab/catalog", { headers: { "X-Dev-GitHub-Login": RESEARCHER } }),
    env,
    ctx
  );
  const body = await res.json();
  await check("lab catalog holds addresses and says they are not publishable", () => {
    const ips = body.hosts.map((h) => h.ip);
    assert.ok(ips.includes(CORPUS_IP), "positive control failed: no address in the gated payload");
    for (const h of body.hosts) {
      assert.equal(h.disclosure.publishable, false, "I-27: unnotified host marked publishable");
    }
  });
  await check("lab responses are marked no-store and name the untrusted fields (I-16)", () => {
    assert.match(res.headers.get("Cache-Control") || "", /no-store/);
    assert.ok(body.untrusted_fields.includes("version"), "I-16 render warning missing");
  });
}

{
  // Notified 91 days ago: the I-27 window has elapsed, so this one is publishable.
  const env = await seededEnv();
  await env.KV.put(
    `discovery:hit:${CORPUS_IP}`,
    JSON.stringify({
      ip: CORPUS_IP,
      port: 11434,
      stack: "ollama",
      stacks: ["ollama"],
      first_seen: daysAgo(200),
      last_seen: daysAgo(2),
      notified_at: daysAgo(91),
      notified_via: "shadowserver",
    })
  );
  const res = await worker.fetch(
    req("GET", "/v1/research/lab/catalog", { headers: { "X-Dev-GitHub-Login": RESEARCHER } }),
    env,
    ctx
  );
  const body = await res.json();
  const row = body.hosts.find((h) => h.ip === CORPUS_IP);
  await check("I-27: publishable only after the disclosure window elapses", () => {
    assert.equal(row.disclosure.publishable, true);
    assert.equal(row.disclosure.reason, "window_elapsed");
  });
}

{
  // I-27's redaction rule was exported, called nowhere and asserted nowhere —
  // so the first surface to adopt it would have been the first to run it.
  const env = await seededEnv();
  await env.KV.put(
    `discovery:hit:${CORPUS_IP_2}`,
    JSON.stringify({
      ip: CORPUS_IP_2,
      port: 8888,
      stack: "jupyter",
      stacks: ["jupyter"],
      first_seen: daysAgo(200),
      last_seen: daysAgo(2),
      country_code: "US",
      notified_at: daysAgo(91),
      notified_via: "shadowserver",
    })
  );
  const res = await worker.fetch(
    req("GET", "/v1/research/lab/catalog?publication=1", {
      headers: { "X-Dev-GitHub-Login": RESEARCHER },
    }),
    env,
    ctx
  );
  const body = await res.json();
  const text = JSON.stringify(body);

  await check("publication mode strips the address of an unnotified host (I-27)", () => {
    assert.equal(body.publication_redacted, true);
    assert.ok(!text.includes(CORPUS_IP), "an un-notified host kept its address");
    const redacted = body.hosts.find((h) => h.redacted);
    assert.ok(redacted, "expected at least one redacted host");
    assert.deepEqual(redacted.redacted, ["ip", "city", "org", "product"]);
    assert.equal(redacted.redaction_reason, "no_notification_attempt");
  });

  await check("a host past its disclosure window keeps its address", () => {
    assert.ok(text.includes(CORPUS_IP_2), "the 91-day-notified host should be publishable");
  });
}

/* ------------------------------------------------------------------ */
section("[N7] one malformed record does not take the lab down with it");

{
  // I-16: every string on a record came from a probed host, so the lab has to
  // survive them. A country_code that is truthy but blank once control
  // characters are stripped made clean() return null, and the chained
  // .toUpperCase() 500'd every route that walks the corpus — catalog, map and
  // validation all die on one row, because normalizeHost runs over all of them.
  const env = await seededEnv();
  await env.KV.put(
    `discovery:hit:${CORPUS_IP}`,
    JSON.stringify({
      ip: CORPUS_IP,
      port: 11434,
      stack: "ollama",
      stacks: ["ollama"],
      first_seen: daysAgo(30),
      last_seen: daysAgo(1),
      country_code: "  ",
      country: " ",
      org: "‮",
    })
  );
  for (const p of ["/v1/research/lab/catalog", "/v1/research/lab/map", "/v1/research/lab/validation"]) {
    const res = await worker.fetch(
      req("GET", p, { headers: { "X-Dev-GitHub-Login": RESEARCHER } }),
      env,
      ctx
    );
    await check(`${p} survives a record with a blank country_code`, async () => {
      assert.equal(res.status, 200, `got ${res.status}: ${(await res.text()).slice(0, 160)}`);
    });
  }
  const host = await worker.fetch(
    req("GET", `/v1/research/lab/host?ip=${CORPUS_IP}`, {
      headers: { "X-Dev-GitHub-Login": RESEARCHER },
    }),
    env,
    ctx
  );
  await check("the single-host route survives it too", () => assert.equal(host.status, 200));
}

{
  // A host exposing two stacks is one host. crossTab counted the single-valued
  // dimension inside the cell loop, so it appeared twice in its own country
  // total — and the map's Σ row then disagreed with the by_country card built
  // by countBy() on the same screen, from the same corpus, in the same response.
  const env = await seededEnv();
  await env.KV.put(
    `discovery:hit:${CORPUS_IP}`,
    JSON.stringify({
      ip: CORPUS_IP,
      port: 11434,
      stack: "ollama",
      stacks: ["ollama", "jupyter"],
      first_seen: daysAgo(30),
      last_seen: daysAgo(1),
      country_code: "DE",
    })
  );
  const res = await worker.fetch(
    req("GET", "/v1/research/lab/map", { headers: { "X-Dev-GitHub-Login": RESEARCHER } }),
    env,
    ctx
  );
  const body = await res.json();
  await check("a multi-stack host counts once in the single-valued dimension", () => {
    const de = body.crosstab.stack_x_country.cols.find((c) => c.key === "DE");
    const card = body.by_country.top.find((c) => c.key === "DE");
    assert.ok(de && card, "expected a DE bucket in both views");
    assert.equal(
      de.hosts,
      card.hosts,
      `cross-tab says ${de.hosts} DE hosts, the by_country card says ${card.hosts}`
    );
  });
}

/* ------------------------------------------------------------------ */
section("[N6] the lab prefix owns its own 404/405 (no fall-through)");

{
  const env = await seededEnv();
  const unknown = await worker.fetch(
    req("GET", "/v1/research/lab/anything", { headers: { "X-Dev-GitHub-Login": RESEARCHER } }),
    env,
    ctx
  );
  const wrongMethod = await worker.fetch(
    req("POST", "/v1/research/lab/catalog", {
      headers: { "X-Dev-GitHub-Login": RESEARCHER },
      body: {},
    }),
    env,
    ctx
  );
  await check("an unknown lab path is 404, not a fall-through to another gate", () =>
    assert.equal(unknown.status, 404)
  );
  await check("the lab is read-only: POST to a lab route is 405", async () => {
    assert.equal(wrongMethod.status, 405);
    assert.equal((await wrongMethod.json()).allow, "GET");
  });
}

{
  const env = await seededEnv();
  // The host route reads a KV key built from the parameter: only literals.
  const traversal = await worker.fetch(
    req("GET", "/v1/research/lab/host?ip=../../allowlist:github:" + RESEARCHER, {
      headers: { "X-Dev-GitHub-Login": RESEARCHER },
    }),
    env,
    ctx
  );
  await check("the host lookup refuses anything that is not an address literal", async () => {
    assert.equal(traversal.status, 400);
    assert.equal((await traversal.json()).error, "invalid_ip");
  });
}

// --- CORS preflight must allow every header the clients actually send -------
// The lab's dev path was unreachable in a browser for as long as it existed:
// the preflight omitted X-Dev-GitHub-Login, so Chrome blocked the real request
// while curl (which ignores CORS) passed every endpoint test. A route that only
// works from curl is a route nobody has opened.
section("CORS preflight allows the headers the clients send");

{
  const env = await seededEnv();
  const pre = await worker.fetch(
    req("OPTIONS", "/v1/research/me", {
      headers: {
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-dev-github-login",
      },
    }),
    env,
    ctx
  );
  const allow = (pre.headers.get("Access-Control-Allow-Headers") || "").toLowerCase();

  await check("preflight allows the Access JWT header", async () => {
    assert.ok(allow.includes("cf-access-jwt-assertion"), allow);
  });
  await check("preflight allows the admin token header", async () => {
    assert.ok(allow.includes("x-admin-token"), allow);
  });
  await check("preflight allows the dev identity header", async () => {
    assert.ok(
      allow.includes("x-dev-github-login"),
      `a browser would block the lab dev path; got: ${allow}`
    );
  });
}

/* ------------------------------------------------------------------ */
// The failure this reproduces: an approved researcher signs in successfully and
// is told they are not on the allowlist, because the approval recorded a GitHub
// handle and the Access assertion presented an email. It only ever worked for
// the maintainer, who had hand-written both spellings.
section("identity: approval and assertion must agree on who someone is");

{
  const { approveResearcher, matchAllowEntry, isAllowed } =
    await import("../src/lib/allowlist.js");

  const env = await seededEnv();
  await approveResearcher(env, {
    login: "MahdiHedhli",
    aliases: ["researcher@identity.example"],
    approved_by: "test",
  });

  await check("the GitHub handle resolves", async () => {
    assert.equal(await isAllowed(env, "mahdihedhli"), true);
  });

  await check("the email alias resolves to the same entry", async () => {
    const m = await matchAllowEntry(env, ["researcher@identity.example"]);
    assert.ok(m, "email alias should match");
    assert.equal(m.entry.login, "mahdihedhli");
  });

  await check("an email local-part cannot impersonate an approved handle", async () => {
    assert.equal(await matchAllowEntry(env, ["mhedhli"]), null);
    assert.ok(await matchAllowEntry(env, ["researcher@identity.example"]));
  });

  await check("an unrelated identity still does not", async () => {
    assert.equal(await matchAllowEntry(env, ["someone-else", "x@y.com"]), null);
  });

  await check("matching reports which name matched", async () => {
    const m = await matchAllowEntry(env, ["nope", "mahdihedhli"]);
    assert.equal(m.matched, "mahdihedhli");
  });
}

{
  const { approveResearcher, revokeResearcher, matchAllowEntry } =
    await import("../src/lib/allowlist.js");
  const env = await seededEnv();
  await approveResearcher(env, {
    login: "rotated", aliases: ["old@example.com"], approved_by: "test",
  });
  await approveResearcher(env, {
    login: "rotated", aliases: ["new@example.com"], approved_by: "test",
  });

  await check("re-approval deactivates aliases removed from the entry", async () => {
    assert.equal(await matchAllowEntry(env, ["old@example.com"]), null);
    assert.ok(await matchAllowEntry(env, ["new@example.com"]));
  });

  await revokeResearcher(env, "rotated");
  await check("revocation after re-approval leaves no stale alias", async () => {
    assert.equal(await matchAllowEntry(env, ["old@example.com"]), null);
    assert.equal(await matchAllowEntry(env, ["new@example.com"]), null);
  });
}

{
  const { approveResearcher } = await import("../src/lib/allowlist.js");
  const env = await seededEnv();
  await approveResearcher(env, {
    login: "owner-one", aliases: ["claimed@example.com"], approved_by: "test",
  });

  await check("an alias cannot overwrite another researcher's identity", async () => {
    await assert.rejects(
      approveResearcher(env, {
        login: "owner-two", aliases: ["claimed@example.com"], approved_by: "test",
      }),
      /alias_in_use/
    );
  });
}

{
  const { approveResearcher, revokeResearcher, matchAllowEntry } =
    await import("../src/lib/allowlist.js");
  const env = await seededEnv();
  await approveResearcher(env, {
    login: "someone", aliases: ["someone@example.com"], approved_by: "test",
  });
  await revokeResearcher(env, "someone");

  await check("revoking takes the aliases with it — no second door", async () => {
    assert.equal(await matchAllowEntry(env, ["someone"]), null);
    assert.equal(await matchAllowEntry(env, ["someone@example.com"]), null);
  });
}

{
  const { approveResearcher, matchAllowEntry } = await import("../src/lib/allowlist.js");
  const env = await seededEnv();
  await approveResearcher(env, {
    login: "narrow",
    // An alias is an identity, not a wildcard: approving one person must not be
    // a way to admit a class of people.
    aliases: ["*", "", "  ", "a b c", "../etc/passwd", "ok@example.com"],
    approved_by: "test",
  });

  await check("junk aliases are refused, legitimate ones kept", async () => {
    assert.equal(await matchAllowEntry(env, ["ok@example.com"]) !== null, true);
    for (const bad of ["*", "a b c", "../etc/passwd"]) {
      assert.equal(await matchAllowEntry(env, [bad]), null, `alias ${bad} must not match`);
    }
  });
}

/* ------------------------------------------------------------------ */
// /v1/research/me said "researcher access" while every lab query returned 403
// on the same session, because the two gates checked different things. Any
// route that gates on identity has to agree with every other one.
section("every gated route resolves identity the same way");

{
  const src = fs.readFileSync(path.join(SRC, "lib", "lab.js"), "utf8");
  const idx = fs.readFileSync(path.join(SRC, "index.js"), "utf8");

  await check("no gate checks a single login instead of all candidates", async () => {
    const offenders = [];
    for (const [name, code] of [["lab.js", src], ["index.js", idx]]) {
      // isAllowed(env, <something>.login) is the shape of the bug: one string
      // where the assertion offered several.
      if (/isAllowed\(\s*env\s*,\s*\w+\.login\s*\)/.test(code)) offenders.push(name);
    }
    assert.deepEqual(offenders, [],
      `these gate on a single identity: ${offenders.join(", ")}`);
  });

  await check("both gates use matchAllowEntry", async () => {
    assert.ok(src.includes("matchAllowEntry"), "lab.js must match all candidates");
    assert.ok(idx.includes("matchAllowEntry"), "index.js must match all candidates");
  });
}

{
  const access = fs.readFileSync(path.join(SRC, "lib", "access.js"), "utf8");
  await check("production identity comes only from exact signed email", async () => {
    assert.ok(!access.includes('X-GitHub-Login'));
    assert.ok(!access.includes('email.split("@")'));
    for (const claim of ["preferred_username", "nickname", "identity_nickname"]) {
      assert.ok(!access.includes(`push(p.${claim})`), `trusted mutable claim ${claim}`);
    }
  });
}

section("the public checker cannot paint an inconclusive result green");

{
  const publicDir = path.join(SRC, "..", "..", "public");
  const page = fs.readFileSync(path.join(publicDir, "index.html"), "utf8");
  const client = fs.readFileSync(path.join(publicDir, "js", "app.js"), "utf8");

  await check("the active hosted-check button is available", async () => {
    assert.match(page, /id="check-btn" disabled>Check my public IP<\/button>/);
    assert.doesNotMatch(page, /Hosted checks are suspended/);
  });

  await check("the hosted checker cannot run before a single-use Turnstile token", async () => {
    assert.match(page, /id="turnstile-widget"/);
    assert.match(page, /script-src 'self' https:\/\/challenges\.cloudflare\.com/);
    assert.match(page, /frame-src https:\/\/challenges\.cloudflare\.com/);
    assert.ok(client.includes("if (!turnstileToken)"));
    assert.ok(client.includes("body.turnstile_token = token"));
    assert.ok(client.includes("window.turnstile.reset(turnstileWidgetId)"));
    assert.ok(client.includes("turnstile/v0/api.js?render=explicit&onload=onLeakyTurnstileLoad"));
    assert.doesNotMatch(client, /console\.(?:log|debug).*token/i);
  });

  await check("HTTP 503 structured reports and target errors render inconclusive", async () => {
    assert.ok(client.includes('data.conclusive === false'));
    assert.ok(client.includes('Array.isArray(data.services)'));
    assert.ok(client.includes('INCONCLUSIVE — do not treat this as a clean result'));
    assert.ok(client.includes('"platform_error", "authorization_error", "target_error"'));
  });
}

finish();
