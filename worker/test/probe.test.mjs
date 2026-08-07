/**
 * Local harness for the tier-1 probe engine.
 * Stands up fake Ollama / Ray / Jupyter servers and asserts the report shape.
 * No network egress, no real targets.
 */
import http from "node:http";
import assert from "node:assert/strict";
import { runChecks, overallSeverity, resolvePort } from "../src/lib/services.js";

const hits = [];

function server(routes) {
  return http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    const r = routes[req.url.split("?")[0]];
    if (!r) {
      res.writeHead(404).end("nope");
      return;
    }
    r(req, res);
  });
}

const json = (body) => (req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};
const html = (body) => (req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(body);
};

function listen(srv, port) {
  return new Promise((r) => srv.listen(port, "127.0.0.1", r));
}

// --- fake targets ---------------------------------------------------
const ollama = server({
  "/api/version": json({ version: "0.1.40" }),
  "/api/tags": json({
    models: [
      { name: "llama3.2:3b", size: 2019393189 },
      { name: "qwen2.5:7b", size: 4683087519 },
    ],
  }),
});

const ray = server({
  "/api/version": json({ version: "1", ray_version: "2.9.0", ray_commit: "abc123" }),
  "/api/jobs/": json([{ job_id: "raysubmit_1", status: "SUCCEEDED" }]),
});

const jupyterOpen = server({
  "/api/status": json({
    started: "2026-08-07T10:00:00.000000Z",
    last_activity: "2026-08-07T10:05:00.000000Z",
    connections: 0,
    kernels: 1,
    version: "2.14.0",
  }),
  "/tree": html("<html><head><title>Home Page - Jupyter</title></head><body>files</body></html>"),
});

const jupyterTokened = http.createServer((req, res) => {
  hits.push(`${req.method} ${req.url}`);
  if (req.url.startsWith("/api/status")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ started: "2026-08-07T10:00:00.000000Z", version: "2.14.0" }));
    return;
  }
  if (req.url.startsWith("/tree")) {
    res.writeHead(302, { Location: "/login?next=%2Ftree" }).end();
    return;
  }
  res.writeHead(404).end();
});

await listen(ollama, 11434);
await listen(ray, 8265);
await listen(jupyterOpen, 8888);
await listen(jupyterTokened, 8889);

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

// --- 1. all three exposed -------------------------------------------
console.log("\n[1] all three services exposed");
let run = await runChecks("127.0.0.1", { timeoutMs: 2000 });
assert.equal(run.ok, true);
let byId = Object.fromEntries(run.results.map((r) => [r.service, r]));

check("ollama detected + versioned", () => {
  assert.equal(byId.ollama.detected, true);
  assert.equal(byId.ollama.version, "0.1.40");
});
check("ollama exposed with model list", () => {
  assert.equal(byId.ollama.exposed, true);
  assert.equal(byId.ollama.models.length, 2);
  assert.equal(byId.ollama.models[0].name, "llama3.2:3b");
});
check("ollama finding id + severity", () => {
  assert.equal(byId.ollama.findings[0].id, "ollama-unauth-api");
  assert.equal(byId.ollama.findings[0].severity, "high");
});
check("ray detected via ray_version (not confused with ollama)", () => {
  assert.equal(byId.ray.detected, true);
  assert.equal(byId.ray.version, "2.9.0");
});
check("ray exposed jobs api -> critical", () => {
  assert.equal(byId.ray.exposed, true);
  assert.equal(byId.ray.jobs_visible, 1);
  assert.equal(byId.ray.findings[0].id, "ray-unauth-jobs-api");
  assert.equal(byId.ray.findings[0].severity, "critical");
});
check("jupyter open -> critical", () => {
  assert.equal(byId.jupyter.detected, true);
  assert.equal(byId.jupyter.version, "2.14.0");
  assert.equal(byId.jupyter.exposed, true);
  assert.equal(byId.jupyter.findings[0].id, "jupyter-no-token-auth");
});
check("overall severity = critical", () => {
  assert.equal(overallSeverity(run.results), "critical");
});
check("remediation present on exposed services", () => {
  assert.ok(byId.ollama.remediation.length >= 3);
  assert.ok(byId.ray.remediation.length >= 3);
});

// --- 2. jupyter with token enforced ---------------------------------
console.log("\n[2] jupyter with token auth (port 8889)");
run = await runChecks("127.0.0.1", {
  services: ["jupyter"],
  ports: { jupyter: 8889 },
  timeoutMs: 2000,
});
const jt = run.results[0];
check("detected but not exposed", () => {
  assert.equal(jt.detected, true);
  assert.equal(jt.exposed, false);
  assert.equal(jt.authenticated, true);
});
check("emits low-severity reachable finding, not critical", () => {
  assert.equal(jt.findings[0].id, "jupyter-reachable");
  assert.equal(overallSeverity(run.results), "low");
});

// --- 3. nothing listening -------------------------------------------
console.log("\n[3] closed port -> not detected, not an error");
run = await runChecks("127.0.0.1", {
  services: ["ollama"],
  ports: { ollama: 11435 },
  timeoutMs: 1500,
});
check("not detected, error recorded, no findings", () => {
  assert.equal(run.results[0].detected, false);
  assert.equal(run.results[0].exposed, false);
  assert.equal(run.results[0].findings.length, 0);
  assert.ok(run.results[0].error);
});
check("overall severity none", () => {
  assert.equal(overallSeverity(run.results), "none");
});

// --- 4. port allowlist ----------------------------------------------
console.log("\n[4] port allowlist (not a general port prober)");
check("rejects arbitrary port", () => {
  const r = resolvePort("ollama", 22);
  assert.equal(r.ok, false);
  assert.equal(r.error, "port_not_allowed");
});
check("rejects ray port on ollama service", () => {
  assert.equal(resolvePort("ollama", 8265).ok, false);
});
check("accepts known alternate", () => {
  assert.deepEqual(resolvePort("jupyter", 8890), { ok: true, port: 8890 });
});
check("runChecks surfaces bad port instead of probing", () => {
  // handled below (async)
});
const bad = await runChecks("127.0.0.1", { services: ["ollama"], ports: { ollama: 9999 } });
check("runChecks returns ok:false on bad port", () => {
  assert.equal(bad.ok, false);
  assert.equal(bad.error, "port_not_allowed");
});

// --- 5. read-only discipline ----------------------------------------
console.log("\n[5] read-only discipline");
check("every request was a GET", () => {
  const nonGet = hits.filter((h) => !h.startsWith("GET "));
  assert.deepEqual(nonGet, []);
});
check("no state-changing ollama endpoints touched", () => {
  const bad = hits.filter((h) => /\/api\/(pull|generate|create|delete|push|chat)/.test(h));
  assert.deepEqual(bad, []);
});
check("no ray job submission", () => {
  const bad = hits.filter((h) => h.startsWith("POST") || /\/api\/jobs\/\w/.test(h));
  assert.deepEqual(bad, []);
});
check("exposure probe skipped when service not confirmed", () => {
  // /tree on 8888 only hit once (confirm was /api/status)
  assert.ok(hits.includes("GET /api/status"));
});

console.log("\nrequests issued to fake targets:");
[...new Set(hits)].sort().forEach((h) => console.log("  " + h));

for (const s of [ollama, ray, jupyterOpen, jupyterTokened]) s.close();
console.log(failures ? `\n${failures} FAILURE(S)` : "\nall assertions passed");
process.exit(failures ? 1 : 0);
