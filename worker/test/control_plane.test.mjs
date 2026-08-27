/**
 * Real Miniflare/Durable Object contract test. No target-facing route is called;
 * every address below is only persisted as permission state.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const ADMIN = "control-plane-test-admin";
const port = 24_000 + Math.floor(Math.random() * 10_000);
const base = `http://127.0.0.1:${port}`;
const persist = await mkdtemp(path.join(tmpdir(), "leaky-control-test-"));
const wrangler = path.resolve("node_modules/.bin/wrangler");

const child = spawn(
  wrangler,
  [
    "dev",
    "--local",
    "--port",
    String(port),
    "--persist-to",
    persist,
    "--show-interactive-dev-session=false",
    "--var",
    `ADMIN_SYNC_TOKEN:${ADMIN}`,
    "--var",
    "ENVIRONMENT:test",
    "--var",
    "CONTROL_PLANE_READY:true",
  ],
  { stdio: ["ignore", "pipe", "pipe"] }
);

let output = "";
child.stdout.on("data", (chunk) => { output += chunk; });
child.stderr.on("data", (chunk) => { output += chunk; });

async function waitReady() {
  for (let i = 0; i < 100; i++) {
    try {
      const response = await fetch(`${base}/v1/admin/control/health`, {
        headers: { "X-Admin-Token": ADMIN },
      });
      if (response.ok) return response.json();
    } catch {
      // Server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`local Worker did not start\n${output}`);
}

async function post(pathname, body) {
  const response = await fetch(`${base}${pathname}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Token": ADMIN,
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

const now = Date.parse("2026-08-27T16:30:00Z");
const provenance = {
  kind: "public_index",
  source: "shodan",
  observed_at: "2026-08-27T12:00:00Z",
};

function candidate(overrides = {}) {
  return {
    purpose: "active_discovery",
    ip: "8.8.8.8",
    asn: "AS15169",
    service: "ollama",
    port: 11434,
    now,
    provenance,
    ...overrides,
  };
}

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (error) {
    failures++;
    console.log(`  FAIL ${name}\n       ${error.message}`);
  }
}

try {
  const health = await waitReady();
  console.log("\n[CP1] durable pre-probe permission state");
  await check("SQLite control plane starts empty", () => {
    assert.deepEqual(
      { ok: health.ok, schema: health.schema, hosts: health.hosts, attempts: health.attempts },
      { ok: true, schema: 1, hosts: 0, attempts: 0 }
    );
  });

  const lease = await post("/v1/admin/discovery/lease", candidate());
  await check("fresh public-index provenance acquires a persisted 14-day lease", () => {
    assert.equal(lease.status, 200);
    assert.equal(lease.body.ok, true);
    assert.equal(lease.body.ip, "8.8.8.8");
    assert.equal(Date.parse(lease.body.next_eligible_at), now + 14 * 86_400_000);
  });

  const consumed = await post("/v1/admin/discovery/permit", {
    permit_id: lease.body.permit_id,
    now,
  });
  await check("a one-time permit can be consumed once", () => {
    assert.equal(consumed.status, 200);
    assert.equal(consumed.body.lease_id, lease.body.lease_id);
  });

  const replay = await post("/v1/admin/discovery/permit", {
    permit_id: lease.body.permit_id,
    now,
  });
  await check("permit replay is refused", () => {
    assert.equal(replay.status, 409);
    assert.equal(replay.body.error, "permit_consumed");
  });

  const repeated = await post("/v1/admin/discovery/lease", candidate());
  await check("a crash or completion cannot erase the 14-day interval", () => {
    assert.equal(repeated.status, 409);
    assert.equal(repeated.body.error, "probe_interval_active");
  });

  const raceLease = await post(
    "/v1/admin/discovery/lease",
    candidate({ ip: "1.1.1.1", asn: "AS13335", service: "ray", port: 8265 })
  );
  const exclusion = await post("/v1/admin/exclusions", {
    entries: ["1.1.1.1"],
    issue_number: 999,
    source: "control-plane-test",
  });
  const raceConsume = await post("/v1/admin/discovery/permit", {
    permit_id: raceLease.body.permit_id,
    now,
  });
  await check("an opt-out filed after lease acquisition wins before emission", () => {
    assert.equal(exclusion.body.control_plane.ok, true);
    assert.equal(raceConsume.status, 403);
    assert.equal(raceConsume.body.error, "target_excluded");
  });

  const stale = await post(
    "/v1/admin/discovery/lease",
    candidate({
      ip: "9.9.9.9",
      asn: "AS19281",
      provenance: { ...provenance, observed_at: "2026-08-01T00:00:00Z" },
    })
  );
  await check("stale provenance cannot become standing permission", () => {
    assert.equal(stale.status, 403);
    assert.equal(stale.body.error, "fresh_public_index_provenance_required");
  });

  const badPort = await post(
    "/v1/admin/discovery/lease",
    candidate({ ip: "208.67.222.222", asn: "AS36692", port: 22 })
  );
  await check("the control plane cannot authorize a general-purpose port", () => {
    assert.equal(badPort.status, 400);
    assert.equal(badPort.body.error, "port_not_allowed");
  });

  const unknown1 = await post(
    "/v1/admin/discovery/lease",
    candidate({ ip: "64.6.64.6", asn: null, service: "jupyter", port: 8888 })
  );
  const unknown2 = await post(
    "/v1/admin/discovery/lease",
    candidate({ ip: "64.6.65.6", asn: null, service: "jupyter", port: 8888 })
  );
  await check("unknown ASN uses one shared conservative bucket", () => {
    assert.equal(unknown1.status, 200);
    assert.equal(unknown1.body.asn, "AS-UNKNOWN");
    assert.equal(unknown2.status, 429);
    assert.equal(unknown2.body.scope, "active_unknown_asn");
  });
} finally {
  child.kill("SIGTERM");
  await new Promise((resolve) => child.once("exit", resolve));
  await rm(persist, { recursive: true, force: true });
}

if (failures) {
  console.error(`\n${failures} control-plane assertion(s) failed`);
  process.exit(1);
}
console.log("\ncontrol-plane tests passed (no target traffic)");
