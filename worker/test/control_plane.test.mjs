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
    "--var",
    "CANARY_PROBE_ENABLED:true",
    "--var",
    "CANARY_TARGET_IP:93.184.216.99",
    "--var",
    "CANARY_TARGET_HOST:canary.example.test",
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

async function get(pathname) {
  const response = await fetch(`${base}${pathname}`, {
    headers: { "X-Admin-Token": ADMIN },
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
      { ok: true, schema: 2, hosts: 0, attempts: 0 }
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

  const firstCompletion = await post("/v1/admin/discovery/complete", {
    lease_id: lease.body.lease_id,
    outcome: "not_observed",
  });
  assert.equal(firstCompletion.status, 200);
  const duplicateCompletion = await post("/v1/admin/discovery/complete", {
    lease_id: lease.body.lease_id,
    outcome: "platform_error",
  });
  await check("a completed outcome cannot be rewritten later", () => {
    assert.equal(duplicateCompletion.status, 409);
    assert.equal(duplicateCompletion.body.error, "lease_not_emitted");
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

  const discoveryCanary = await post(
    "/v1/admin/discovery/lease",
    candidate({ service: "owned_canary", port: 8443 })
  );
  const wrongCanary = await post("/v1/admin/discovery/lease", {
    purpose: "owned_canary",
    ip: "93.184.216.98",
    service: "owned_canary",
    port: 8443,
    now,
  });
  const ownedCanary = await post("/v1/admin/discovery/lease", {
    purpose: "owned_canary",
    ip: "93.184.216.99",
    service: "owned_canary",
    port: 8443,
    now,
  });
  await check("the canary profile is isolated to the exact configured owned target", () => {
    assert.equal(discoveryCanary.status, 403);
    assert.equal(discoveryCanary.body.error, "owned_canary_profile_reserved");
    assert.equal(wrongCanary.status, 403);
    assert.equal(wrongCanary.body.error, "owned_canary_not_authorized");
    assert.equal(ownedCanary.status, 200);
  });

  console.log("\n[CP2] authoritative corpus lifecycle");
  const hostRecords = Array.from({ length: 7 }, (_, i) => ({
    ip: `23.0.0.${i + 1}`,
    port: 11434,
    stack: "ollama",
    asn: "AS64500",
    country_code: "US",
    source: "public_index:shodan",
    first_seen: "2026-08-01T00:00:00Z",
    last_seen: "2026-08-27T00:00:00Z",
  }));
  const inserted = await post("/v1/admin/control/hosts", { records: hostRecords });
  await check("minimized host rows are accepted into the strong store", () => {
    assert.equal(inserted.status, 200);
    assert.equal(inserted.body.accepted, 7);
  });

  let cursor = "";
  const paged = [];
  do {
    const page = await get(`/v1/admin/control/hosts?limit=3${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
    assert.equal(page.status, 200);
    paged.push(...page.body.records);
    cursor = page.body.next_cursor || "";
  } while (cursor);
  await check("authoritative pagination reaches every row without an offset", () => {
    assert.deepEqual(paged.map((row) => row.ip), hostRecords.map((row) => row.ip));
  });

  const importedAttempt = await post("/v1/admin/control/attempts/import", {
    attempts: [{ ip: "23.0.0.7", asn: "AS64500", last_attempt_at: "2026-08-20T00:00:00Z" }],
  });
  assert.equal(importedAttempt.status, 200);
  const attemptPage = await get("/v1/admin/control/attempts?limit=2");
  await check("the authoritative attempt ledger is cursor-paginated", () => {
    assert.equal(attemptPage.status, 200);
    assert.equal(attemptPage.body.attempts.length, 2);
    assert.ok(attemptPage.body.next_cursor);
    assert.match(attemptPage.body.attempts[0].last_attempt_at, /^2026-/);
  });
  const directExclusion = await post("/v1/admin/control/exclusions", { entries: ["23.0.0.7"] });
  const purgeId = directExclusion.body.purge_jobs?.[0]?.id;
  let purge;
  for (let i = 0; i < 30; i++) {
    purge = await post("/v1/admin/control/purge", { id: purgeId, limit: 2 });
    if (purge.body.job?.status === "complete") break;
  }
  await check("a late-page opt-out purges hosts and attempts, then emits a verified receipt", async () => {
    assert.equal(purge.status, 200);
    assert.equal(purge.body.job.status, "complete");
    assert.equal(purge.body.receipt.verified_zero_matches, true);
    const page = await get("/v1/admin/control/hosts?limit=20");
    assert.equal(page.body.records.some((row) => row.ip === "23.0.0.7"), false);
  });

  const excludedReinsert = await post("/v1/admin/control/hosts", { records: [hostRecords[6]] });
  await check("an active opt-out also blocks a late corpus write", () => {
    assert.equal(excludedReinsert.body.accepted, 0);
    assert.equal(excludedReinsert.body.rejected[0].error, "target_excluded");
  });

  const expired = await post("/v1/admin/control/hosts", {
    records: [{
      ip: "24.0.0.1",
      port: 8888,
      stack: "jupyter",
      source: "public_index:shodan",
      first_seen: "2025-01-01T00:00:00Z",
      last_seen: "2025-01-01T00:00:00Z",
    }],
  });
  assert.equal(expired.body.accepted, 1);
  const retention = await post("/v1/admin/control/retention", { now, limit: 2 });
  await check("indexed retention removes due rows in bounded resumable batches", () => {
    assert.equal(retention.status, 200);
    assert.equal(retention.body.deleted, 1);
    assert.equal(retention.body.complete, true);
  });

  const retiringIp = "23.1.1.1";
  const retiring = await post("/v1/admin/control/hosts", {
    records: [{
      ip: retiringIp,
      port: 11434,
      stack: "ollama",
      source: "public_index:shodan",
      index_observed_at: provenance.observed_at,
      first_seen: "2026-02-28T00:00:00Z",
      last_seen: "2026-02-28T00:00:00Z",
    }],
  });
  assert.equal(retiring.body.accepted, 1);
  const due = await get("/v1/admin/control/expiring?days=179&limit=2");
  await check("the final-verification queue is authoritative and paginated", () => {
    assert.equal(due.status, 200);
    assert.equal(due.body.due.some((row) => row.ip === retiringIp), true);
  });
  const prematureRetire = await post("/v1/admin/control/retire", {
    ips: [retiringIp],
    reason: "final_probe_no_answer",
  });
  await check("a host cannot be retired without a conclusive persisted attempt", () => {
    assert.equal(prematureRetire.body.retired, 0);
    assert.equal(
      prematureRetire.body.results[0].reason,
      "verified_retirement_evidence_required"
    );
  });
  const retiringLease = await post(
    "/v1/admin/discovery/lease",
    candidate({ ip: retiringIp, asn: "AS64501" })
  );
  assert.equal(retiringLease.status, 200);
  const retiringPermit = await post("/v1/admin/discovery/permit", {
    permit_id: retiringLease.body.permit_id,
    now,
  });
  assert.equal(retiringPermit.status, 200);
  const retiringComplete = await post("/v1/admin/discovery/complete", {
    lease_id: retiringLease.body.lease_id,
    outcome: "target_error",
  });
  assert.equal(retiringComplete.status, 200);
  const verifiedRetire = await post("/v1/admin/control/retire", {
    ips: [retiringIp],
    reason: "final_probe_no_answer",
  });
  await check("evidence-backed retirement deletes the host and keeps its attempt ledger", async () => {
    assert.equal(verifiedRetire.body.retired, 1);
    const hosts = await get("/v1/admin/control/hosts?limit=20");
    assert.equal(hosts.body.records.some((row) => row.ip === retiringIp), false);
    const attempts = await get("/v1/admin/control/attempts?limit=20");
    assert.equal(attempts.body.attempts.some((row) => row.ip === retiringIp), true);
  });

  let reconciliation;
  for (let i = 0; i < 20; i++) {
    reconciliation = await post("/v1/admin/control/reconcile", { limit: 2 });
    if (reconciliation.body.complete) break;
  }
  const aggregates = await get("/v1/admin/control/aggregates");
  await check("only a complete aggregate generation becomes current", () => {
    assert.equal(reconciliation.body.complete, true);
    assert.equal(aggregates.status, 200);
    assert.equal(aggregates.body.dimensions.corpus.reverified_hosts, 6);
    assert.equal(aggregates.body.dimensions.stack.ollama, 6);
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
