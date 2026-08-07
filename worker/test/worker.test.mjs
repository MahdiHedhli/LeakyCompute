/**
 * Integration test through the actual Worker fetch handler.
 * Uses an in-memory KV stub so rate limiting, stats and abuse logging all run.
 */
import http from "node:http";
import assert from "node:assert/strict";
import worker from "../src/index.js";


// --- in-memory KV stub ----------------------------------------------
function makeKV() {
  const store = new Map();
  return {
    _store: store,
    async get(k, type) {
      const v = store.get(k);
      if (v === undefined) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(k, v) {
      store.set(k, v);
    },
  };
}

const json = (body) => (req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

function listen(srv, port) {
  return new Promise((r) => srv.listen(port, "127.0.0.1", r));
}

const ollama = http.createServer((req, res) => {
  if (req.url === "/api/version") return json({ version: "0.6.2" })(req, res);
  if (req.url === "/api/tags")
    return json({ models: [{ name: "llama3.2:3b", size: 2019393189 }] })(req, res);
  res.writeHead(404).end();
});
const ray = http.createServer((req, res) => {
  if (req.url === "/api/version")
    return json({ version: "1", ray_version: "2.9.0" })(req, res);
  if (req.url === "/api/jobs/") return json([])(req, res);
  res.writeHead(404).end();
});
await listen(ollama, 11434);
await listen(ray, 8265);

// --- harness ---------------------------------------------------------
const pending = [];
const ctx = { waitUntil: (p) => pending.push(p.catch(() => {})) };
let env;
function freshEnv(overrides = {}) {
  return {
    KV: makeKV(),
    ENVIRONMENT: "test",
    ALLOWED_ORIGINS: "https://mahdihedhli.github.io",
    CHECK_TIMEOUT_MS: "1500",
    RL_OWN_MAX: "3",
    RL_OWN_DAY_MAX: "12",
    RL_GLOBAL_DAY_MAX: "800",
    ...overrides,
  };
}

function post(body, headers = {}) {
  return new Request("https://api.test/v1/check", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": "127.0.0.1",
      Origin: "https://mahdihedhli.github.io",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

// --- 1. default self-check, zero user input --------------------------
console.log("\n[1] POST /v1/check with empty body (own egress IP)");
env = freshEnv();
let res = await worker.fetch(post({}), env, ctx);
let data = await res.json();

await check("200 with structured report", () => {
  assert.equal(res.status, 200);
  assert.equal(data.ok, true);
  assert.equal(data.mode, "own_ip");
  assert.equal(data.services.length, 3);
});
await check("client IP is never echoed back in any result field", () => {
  assert.equal(data.target, "your_egress_ip");
  // remediation prose legitimately mentions 127.0.0.1; check the data fields.
  for (const s of data.services) {
    assert.ok(!("host" in s), "service result must not carry the probed host");
    assert.ok(!JSON.stringify({ ...s, remediation: [], findings: [] }).includes("127.0.0.1"));
  }
});
await check("per-service results carry findings + remediation", () => {
  const o = data.services.find((s) => s.service === "ollama");
  assert.equal(o.detected, true);
  assert.equal(o.version, "0.6.2");
  assert.equal(o.exposed, true);
  assert.equal(o.findings[0].id, "ollama-unauth-api");
  assert.ok(o.remediation.length >= 3);
});
await check("ray exposed even with an empty job list", () => {
  const r = data.services.find((s) => s.service === "ray");
  assert.equal(r.exposed, true);
  assert.equal(r.jobs_visible, 0);
  assert.equal(r.findings[0].severity, "critical");
});
await check("jupyter not running -> not detected, no finding", () => {
  const j = data.services.find((s) => s.service === "jupyter");
  assert.equal(j.detected, false);
  assert.deepEqual(j.findings, []);
});
await check("overall severity is the worst confirmed finding", () => {
  assert.equal(data.overall_severity, "critical");
  assert.equal(data.any_exposed, true);
});
await check("limitations disclosed", () => {
  assert.ok(/not proof of safety/i.test(data.limitations));
});
await check("legacy fields preserved for the deployed front-end", () => {
  assert.equal(data.exposed, true);
  assert.equal(data.port, 11434);
  assert.equal(data.models[0].name, "llama3.2:3b");
  assert.equal(typeof data.latency_ms, "number");
});

// --- 2. attestation gate --------------------------------------------
console.log("\n[2] override requires attestation");
env = freshEnv();
res = await worker.fetch(post({ target: "example.com" }), env, ctx);
data = await res.json();
await check("no attestation -> 400 authorization_required", () => {
  assert.equal(res.status, 400);
  assert.equal(data.error, "authorization_required");
});
await check("refusal logged for abuse review", () => {
  const keys = [...env.KV._store.keys()].filter((k) => k.startsWith("abuse:"));
  assert.equal(keys.length, 1);
  const e = JSON.parse(env.KV._store.get(keys[0]));
  assert.equal(e.result, "override_denied");
  assert.equal(e.reason, "missing_authorization");
});
await check("abuse log stores hashed target, never the raw host", () => {
  const keys = [...env.KV._store.keys()].filter((k) => k.startsWith("abuse:"));
  const raw = env.KV._store.get(keys[0]);
  assert.ok(!raw.includes("example.com"));
});

env = freshEnv();
res = await worker.fetch(post({ target: "10.0.0.5", authorized: true }), env, ctx);
data = await res.json();
await check("private target rejected even with attestation", () => {
  assert.equal(res.status, 400);
  assert.equal(data.error, "private_target_not_allowed");
});

// --- 3. port allowlist ----------------------------------------------
console.log("\n[3] not a general-purpose port prober");
env = freshEnv();
res = await worker.fetch(post({ ports: { ollama: 22 } }), env, ctx);
data = await res.json();
await check("SSH port rejected before any probe is sent", () => {
  assert.equal(res.status, 400);
  assert.equal(data.error, "port_not_allowed");
  assert.deepEqual(data.allowed_ports, [11434, 11435]);
});
env = freshEnv();
res = await worker.fetch(post({ port: 3306 }), env, ctx);
await check("legacy bare `port` also goes through the allowlist", async () => {
  assert.equal(res.status, 400);
});

// --- 4. rate limiting ------------------------------------------------
console.log("\n[4] rate limiting per source IP");
env = freshEnv({ RL_OWN_MAX: "2" });
const codes = [];
for (let i = 0; i < 4; i++) {
  const r = await worker.fetch(post({}), env, ctx);
  codes.push(r.status);
}
await check("blocks after RL_OWN_MAX in the window", () => {
  assert.deepEqual(codes, [200, 200, 429, 429]);
});
await check("429 body names the scope", async () => {
  const r = await worker.fetch(post({}), env, ctx);
  const b = await r.json();
  assert.equal(b.error, "rate_limited");
  assert.equal(b.scope, "own_ip");
});

// --- 5. stats aggregation -------------------------------------------
console.log("\n[5] stats + hit store");
env = freshEnv();
await worker.fetch(post({}), env, ctx);
await Promise.all(pending.splice(0));
const stats = JSON.parse(env.KV._store.get("stats:live"));
await check("per-service tallies recorded", () => {
  assert.equal(stats.by_service.ollama.exposed, 1);
  assert.equal(stats.by_service.ray.exposed, 1);
  assert.equal(stats.by_service.jupyter.detected, 0);
});
await check("one hit record per host, both stacks merged (no clobber)", () => {
  const hitKeys = [...env.KV._store.keys()].filter((k) => k.startsWith("discovery:hit:"));
  assert.equal(hitKeys.length, 1);
  const hit = JSON.parse(env.KV._store.get(hitKeys[0]));
  assert.deepEqual(hit.stacks.slice().sort(), ["ollama", "ray"]);
  assert.deepEqual(hit.ports.slice().sort((a, b) => a - b), [8265, 11434]);
});
await check("by_stack counts both stacks", () => {
  const byStack = JSON.parse(env.KV._store.get("stats:by_stack"));
  assert.equal(byStack.ollama, 1);
  assert.equal(byStack.ray, 1);
});

// --- 6. public stats endpoint ---------------------------------------
console.log("\n[6] GET /v1/stats");
res = await worker.fetch(
  new Request("https://api.test/v1/stats", {
    headers: { Origin: "https://mahdihedhli.github.io" },
  }),
  env,
  ctx
);
const s = await res.json();
await check("exposes by_service, no raw IPs", () => {
  assert.equal(res.status, 200);
  assert.ok(s.live_instrumented.by_service);
  assert.ok(!JSON.stringify(s).includes("127.0.0.1"));
});
await check("CORS honours the allowlist", () => {
  assert.equal(
    res.headers.get("Access-Control-Allow-Origin"),
    "https://mahdihedhli.github.io"
  );
});

ollama.close();
ray.close();
console.log(failures ? `\n${failures} FAILURE(S)` : "\nall assertions passed");
process.exit(failures ? 1 : 0);
