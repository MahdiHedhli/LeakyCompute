/**
 * Real Miniflare/Durable Object contract test. No target-facing route is called;
 * every address below is only persisted as permission state.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { authoritativeNow, DiscoveryControlPlane } from "../src/control_plane.js";

const ADMIN = "control-plane-test-admin";
const NOMINATOR = "control-plane-test-nominator";
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
    "CONTROL_PLANE_TEST_TIME_ENABLED:true",
    "CONTROL_PLANE_TEST_MAINTENANCE_BUDGET_ENABLED:true",
    "--var",
    "SHODAN_MONTHLY_QUERY_BUDGET:10",
    "--var",
    "SHODAN_MONTHLY_QUERY_RESERVE:2",
    "--var",
    `DISCOVERY_NOMINATOR_TOKEN:${NOMINATOR}`,
    "--var",
    "CANARY_PROBE_ENABLED:true",
    "--var",
    "OWNED_CANARY_TARGET_IP:93.184.216.99",
    "--var",
    "OWNED_CANARY_TARGET_HOST:canary.example.test",
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

async function postNominator(body, token = NOMINATOR) {
  return postNominatorPath("/v1/nominator/discovery/nominations", body, token);
}

async function postNominatorPath(pathname, body, token = NOMINATOR) {
  const response = await fetch(`${base}${pathname}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Nominator-Token": token,
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
  ip: "8.8.8.8",
  asn: "AS15169",
  lane: "ollama",
  port: 11434,
};

function candidate(overrides = {}) {
  const value = {
    purpose: "active_discovery",
    ip: "8.8.8.8",
    asn: "AS15169",
    service: "ollama",
    port: 11434,
    now,
    provenance,
    ...overrides,
  };
  if (!Object.hasOwn(overrides, "provenance")) {
    value.provenance = {
      ...provenance,
      ip: value.ip,
      asn: value.asn,
      lane: value.service,
      port: value.port,
    };
  }
  return value;
}

async function nominate(overrides = {}) {
  const value = candidate(overrides);
  const response = await postNominator({
    nominations: [{
      ip: value.provenance?.ip ?? value.ip,
      asn: value.provenance?.asn ?? value.asn,
      service: value.provenance?.lane ?? value.service,
      port: value.provenance?.port ?? value.port,
      source: value.provenance?.source,
      observed_at: value.provenance?.observed_at,
      country_code: "US",
    }],
    now: value.now,
  });
  return response;
}

async function leaseCandidate(overrides = {}) {
  const nomination = await nominate(overrides);
  if (nomination.status !== 200 || nomination.body.created?.length !== 1) {
    return { nomination, lease: null };
  }
  const lease = await post("/v1/admin/discovery/lease", {
    nomination_id: nomination.body.created[0],
    now: candidate(overrides).now,
  });
  return { nomination, lease };
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
  const alarmProbe = Object.create(DiscoveryControlPlane.prototype);
  let scheduledAlarm = null;
  alarmProbe.alarmScheduling = Promise.resolve();
  alarmProbe.ctx = {
    storage: {
      getAlarm: async () => scheduledAlarm,
      setAlarm: async (at) => { scheduledAlarm = at; },
    },
    waitUntil: () => {},
  };
  const sooner = Date.now() + 5_000;
  alarmProbe.scheduleEarliestAlarm(sooner);
  alarmProbe.scheduleEarliestAlarm(Date.now() + 180 * 86_400_000);
  await alarmProbe.alarmScheduling;
  await check("a later retention alarm cannot replace an earlier maintenance continuation", () => {
    assert.equal(scheduledAlarm, sooner);
  });
  await check("production permission clocks ignore caller-supplied time", () => {
    const supplied = Date.now() + 365 * 86_400_000;
    const before = Date.now();
    const actual = authoritativeNow({ ENVIRONMENT: "production" }, { now: supplied });
    const after = Date.now();
    assert.ok(actual >= before && actual <= after);
    assert.equal(
      authoritativeNow(
        { ENVIRONMENT: "test", CONTROL_PLANE_TEST_TIME_ENABLED: "true" },
        { now: supplied }
      ),
      supplied
    );
  });
  await check("SQLite control plane starts empty", () => {
    assert.deepEqual(
      { ok: health.ok, schema: health.schema, hosts: health.hosts, attempts: health.attempts },
      { ok: true, schema: 3, hosts: 0, attempts: 0 }
    );
  });

  const unauthorizedNomination = await postNominator({ nominations: [{}] }, "wrong-token");
  await check("the discovery-admin role cannot create passive nominations", () => {
    assert.equal(unauthorizedNomination.status, 401);
  });

  const budgetNow = Date.parse("2026-08-31T23:59:00Z");
  const sourceUnits = [];
  for (let i = 0; i < 8; i++) {
    sourceUnits.push(await postNominatorPath(
      "/v1/nominator/discovery/source-budget/consume",
      { units: 1, now: budgetNow }
    ));
  }
  await check("the month-paced source ledger is shared and fail-closed", () => {
    assert.equal(sourceUnits.filter((result) => result.status === 200).length, 7);
    assert.equal(sourceUnits.at(-1).status, 429);
    assert.equal(sourceUnits.at(-1).body.error, "source_budget_pacing_exhausted");
    assert.equal(sourceUnits.at(-1).body.consumed, 7);
    assert.equal(sourceUnits.at(-1).body.reserve, 2);
    assert.equal(sourceUnits.at(-1).body.monthly_limit, 10);
  });

  const { nomination: firstNomination, lease } = await leaseCandidate();
  await check("fresh public-index provenance acquires a persisted 14-day lease", () => {
    assert.equal(lease.status, 200);
    assert.equal(lease.body.ok, true);
    assert.equal(lease.body.ip, "8.8.8.8");
    assert.equal(Date.parse(lease.body.next_eligible_at), now + 14 * 86_400_000);
  });
  const reusedNomination = await post("/v1/admin/discovery/lease", {
    nomination_id: firstNomination.body.created[0],
    now,
  });
  await check("an opaque nomination can authorize only one lease", () => {
    assert.equal(reusedNomination.status, 404);
    assert.equal(reusedNomination.body.error, "nomination_not_available");
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

  const { lease: repeated } = await leaseCandidate();
  await check("a crash or completion cannot erase the 14-day interval", () => {
    assert.equal(repeated.status, 409);
    assert.equal(repeated.body.error, "probe_interval_active");
  });

  const { lease: raceLease } = await leaseCandidate({
    ip: "1.1.1.1", asn: "AS13335", service: "ray", port: 8265,
  });
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

  const stale = await nominate({
      ip: "9.9.9.9",
      asn: "AS19281",
      provenance: { ...provenance, observed_at: "2026-08-01T00:00:00Z" },
    });
  await check("stale provenance cannot become standing permission", () => {
    assert.equal(stale.status, 200);
    assert.equal(stale.body.created.length, 0);
    assert.equal(stale.body.rejected[0].error, "invalid_public_index_nomination");
  });

  const badPort = await nominate({ ip: "208.67.222.222", asn: "AS36692", port: 22 });
  await check("the control plane cannot authorize a general-purpose port", () => {
    assert.equal(badPort.body.created.length, 0);
    assert.equal(badPort.body.rejected[0].error, "invalid_public_index_nomination");
  });

  const unknown1 = await nominate({
    ip: "64.6.64.6", asn: null, service: "jupyter", port: 8888,
  });
  await check("active discovery without a usable ASN fails closed", () => {
    assert.equal(unknown1.body.created.length, 0);
    assert.equal(unknown1.body.rejected[0].error, "invalid_public_index_nomination");
  });

  const exactNomination = await nominate({ ip: "64.6.65.6", asn: "AS15169" });
  const swapped = await post("/v1/admin/discovery/lease", {
    nomination_id: exactNomination.body.created[0],
    ip: "64.6.65.7",
    service: "ray",
    port: 8265,
    now,
  });
  await check("an opaque nomination cannot be moved to another target or service", () => {
    assert.equal(swapped.status, 400);
    assert.equal(swapped.body.error, "immutable_nomination_required");
  });

  const hostedA = await post("/v1/admin/discovery/lease", {
    purpose: "hosted_self", ip: "64.6.65.7", asn: "AS19281", service: "ollama", port: 11434, now,
  });
  await check("the discovery route cannot mint a hosted-self permit", () => {
    assert.equal(hostedA.status, 403);
    assert.equal(hostedA.body.error, "purpose_not_authorized_for_route");
  });

  const directLegacyLease = await post("/v1/admin/discovery/lease", candidate({
    ip: "64.6.65.7", asn: "AS19281", service: "ray", port: 8265,
  }));
  await check("caller-supplied target and provenance copies cannot authorize a lease", () => {
    assert.equal(directLegacyLease.status, 400);
    assert.equal(directLegacyLease.body.error, "immutable_nomination_required");
  });

  const discoveryCanary = await nominate({ service: "owned_canary", port: 80 });
  const wrongCanary = await post("/v1/admin/discovery/lease", {
    purpose: "owned_canary",
    ip: "93.184.216.98",
    service: "owned_canary",
    port: 80,
    now,
  });
  const ownedCanary = await post("/v1/admin/discovery/lease", {
    purpose: "owned_canary",
    ip: "93.184.216.99",
    service: "owned_canary",
    port: 80,
    now,
  });
  await check("the canary profile is isolated to the exact configured owned target", () => {
    assert.equal(discoveryCanary.body.created.length, 0);
    assert.equal(discoveryCanary.body.rejected[0].error, "invalid_public_index_nomination");
    assert.equal(wrongCanary.status, 403);
    assert.equal(wrongCanary.body.error, "purpose_not_authorized_for_route");
    assert.equal(ownedCanary.status, 403);
    assert.equal(ownedCanary.body.error, "purpose_not_authorized_for_route");
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
  const duringPurge = await post("/v1/admin/control/reconcile", { limit: 2 });
  await check("a pending purge blocks aggregate publication", () => {
    assert.equal(duringPurge.status, 409);
    assert.equal(duringPurge.body.error, "purge_pending");
  });
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
  const { lease: retiringLease } = await leaseCandidate({ ip: retiringIp, asn: "AS64501" });
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
  let firstPageBucketWrites;
  for (let i = 0; i < 20; i++) {
    reconciliation = await post("/v1/admin/control/reconcile", { limit: 2 });
    if (i === 0) firstPageBucketWrites = reconciliation.body.bucket_writes;
    if (reconciliation.body.complete) break;
  }
  const aggregates = await get("/v1/admin/control/aggregates");
  await check("only a complete aggregate generation becomes current", () => {
    assert.equal(reconciliation.body.complete, true);
    assert.equal(aggregates.status, 200);
    assert.equal(aggregates.body.dimensions.corpus.reverified_hosts, 6);
    assert.equal(aggregates.body.dimensions.stack.ollama, 6);
    assert.equal(firstPageBucketWrites, 5);
    assert.equal(aggregates.body.last_reverified_at, "2026-08-27T00:00:00.000Z");
  });

  const reused = await post("/v1/admin/control/reconcile", { limit: 2 });
  const identical = await post("/v1/admin/control/hosts", { records: [hostRecords[0]] });
  const reusedAgain = await post("/v1/admin/control/reconcile", { limit: 2 });
  await check("unchanged corpus reuses its complete generation without host or bucket writes", () => {
    assert.equal(reused.body.reused, true);
    assert.equal(reused.body.scanned, 0);
    assert.equal(reused.body.generation_id, aggregates.body.generation_id);
    assert.equal(identical.body.accepted, 1);
    assert.equal(identical.body.changed, false);
    assert.equal(reusedAgain.body.reused, true);
    assert.equal(reusedAgain.body.generation_id, aggregates.body.generation_id);
  });

  const newerAnswer = await post("/v1/admin/control/hosts", {
    records: [{ ...hostRecords[0], last_seen: "2026-09-01T00:00:00Z" }],
  });
  let refreshed;
  for (let i = 0; i < 20; i++) {
    refreshed = await post("/v1/admin/control/reconcile", { limit: 2 });
    if (refreshed.body.complete) break;
  }
  const freshAggregates = await get("/v1/admin/control/aggregates");
  await check("a newer successful answer advances freshness and rebuilds the generation", () => {
    assert.equal(newerAnswer.body.changed, true);
    assert.equal(refreshed.body.complete, true);
    assert.notEqual(refreshed.body.generation_id, aggregates.body.generation_id);
    assert.equal(freshAggregates.body.last_reverified_at, "2026-09-01T00:00:00.000Z");
    assert.equal(freshAggregates.body.dimensions.corpus.reverified_hosts, 6);
  });

  await post("/v1/admin/control/hosts", { records: [{
    ...hostRecords[1], stack: "ray", port: 8265,
  }] });
  const interrupted = await post("/v1/admin/control/reconcile", { limit: 2 });
  const stillCurrent = await get("/v1/admin/control/aggregates");
  await post("/v1/admin/control/hosts", { records: [{
    ...hostRecords[0], country_code: "CA",
  }] });
  await post("/v1/admin/control/hosts", { records: [{
    ...hostRecords[2], last_seen: "2026-09-02T00:00:00Z",
  }] });
  const restarted = await post("/v1/admin/control/reconcile", { limit: 2 });
  let resumed = restarted;
  for (let i = 0; i < 20 && !resumed.body.complete; i++) {
    resumed = await post("/v1/admin/control/reconcile", { limit: 2 });
  }
  const afterRestart = await get("/v1/admin/control/aggregates");
  await check("a mid-build host change keeps staging accurate without restarting", () => {
    assert.equal(interrupted.body.complete, false);
    assert.equal(stillCurrent.body.generation_id, freshAggregates.body.generation_id);
    assert.equal(restarted.body.generation_id, interrupted.body.generation_id);
    assert.equal(resumed.body.complete, true);
    assert.equal(afterRestart.body.dimensions.stack.ray, 1);
    assert.equal(afterRestart.body.dimensions.corpus.reverified_hosts, 6);
    assert.equal(afterRestart.body.dimensions.country.CA, 1);
    assert.equal(afterRestart.body.dimensions.country.US, 5);
    assert.equal(afterRestart.body.last_reverified_at, "2026-09-02T00:00:00.000Z");
  });

  await post("/v1/admin/control/hosts", { records: [{
    ...hostRecords[3], last_seen: "2026-09-03T00:00:00Z",
  }] });
  const capped = await post("/v1/admin/control/reconcile", {
    limit: 2, maintenance_write_budget: resumed.body.maintenance_writes_used + 1,
  });
  const beforeContinuation = await get("/v1/admin/control/aggregates");
  const deferredHealth = await get("/v1/admin/control/health");
  await check("a maintenance budget stop keeps the page checkpoint and last complete publication", () => {
    assert.equal(capped.body.maintenance_budget_exhausted, true);
    assert.equal(capped.body.complete, false);
    assert.equal(beforeContinuation.body.generation_id, afterRestart.body.generation_id);
    assert.equal(deferredHealth.body.maintenance_deferred, true);
  });
  for (let i = 0; i < 20; i++) {
    const step = await post("/v1/admin/control/reconcile", { limit: 2 });
    if (step.body.complete) break;
  }
  const resumedHealth = await get("/v1/admin/control/health");
  await check("a completed continuation releases the discovery preflight hold", () => {
    assert.equal(resumedHealth.body.maintenance_deferred, false);
  });

  await post("/v1/admin/control/hosts", { records: [{
    ip: "24.0.0.2", port: 8888, stack: "jupyter", source: "public_index:shodan",
    first_seen: "2025-01-01T00:00:00Z", last_seen: "2025-01-01T00:00:00Z",
  }] });
  const retentionFirst = await post("/v1/admin/control/reconcile", { limit: 2 });
  const afterRetention = await get("/v1/admin/control/hosts?limit=20");
  await check("reconciliation drains overdue retention before scanning or reusing a generation", () => {
    assert.equal(retentionFirst.body.complete, false);
    assert.equal(retentionFirst.body.retention_pending, true);
    assert.equal(afterRetention.body.records.some((row) => row.ip === "24.0.0.2"), false);
  });
  for (let i = 0; i < 20; i++) {
    const step = await post("/v1/admin/control/reconcile", { limit: 2 });
    if (step.body.complete) break;
  }

  const approved = await post("/v1/admin/allowlist", {
    op: "approve", login: "researcher-one", aliases: ["researcher@example.test"],
  });
  const revoked = await post("/v1/admin/allowlist", {
    op: "revoke", login: "researcher-one",
  });
  await check("research authorization responses never return email aliases", () => {
    assert.deepEqual(
      { status: approved.status, active: approved.body.active, login: approved.body.login },
      { status: 200, active: true, login: "researcher-one" }
    );
    assert.deepEqual(
      { status: revoked.status, active: revoked.body.active, login: revoked.body.login },
      { status: 200, active: false, login: "researcher-one" }
    );
    assert.equal(JSON.stringify(approved.body).includes("researcher@example.test"), false);
  });

  const dayOne = Date.parse("2026-10-03T12:00:00Z");
  const dayTwo = Date.parse("2026-10-05T12:00:00Z");
  const expiringFirst = await post("/v1/admin/control/hosts", { records: [{
    ip: "1.0.0.1", port: 11434, stack: "ollama", source: "public_index:shodan",
    first_seen: "2026-04-07T00:00:00Z", last_seen: "2026-04-07T00:00:00Z",
  }] });
  assert.equal(expiringFirst.body.accepted, 1);
  const dayOnePage = await post("/v1/admin/control/reconcile", { limit: 2, now: dayOne });
  const dayOneStop = await post("/v1/admin/control/reconcile", {
    limit: 2, now: dayOne,
    maintenance_write_budget: dayOnePage.body.maintenance_writes_used + 1,
  });
  const expiredDuringBuild = await post("/v1/admin/control/retention", { limit: 2, now: dayTwo });
  let dayTwoPage;
  for (let i = 0; i < 20; i++) {
    dayTwoPage = await post("/v1/admin/control/reconcile", { limit: 2, now: dayTwo });
    if (dayTwoPage.body.complete) break;
  }
  const afterMultiDay = await get("/v1/admin/control/aggregates");
  await check("a deferred generation survives UTC rollover and a scanned host's expiry", () => {
    assert.equal(dayOnePage.body.complete, false);
    assert.equal(dayOneStop.body.maintenance_budget_exhausted, true);
    assert.equal(expiredDuringBuild.body.deleted, 1);
    assert.equal(dayTwoPage.body.complete, true);
    assert.equal(dayTwoPage.body.generation_id, dayOnePage.body.generation_id);
    assert.equal(afterMultiDay.body.dimensions.corpus.reverified_hosts, 6);
  });

  const asnOptOut = await post("/v1/admin/control/exclusions", { entries: ["AS64555"] });
  const { lease: unverifiedAsnLease } = await leaseCandidate({
    ip: "64.6.65.8", asn: "AS64556",
  });
  await check("an ASN-wide opt-out pauses discovery without independent BGP mapping", () => {
    assert.equal(asnOptOut.status, 200);
    assert.equal(unverifiedAsnLease.status, 503);
    assert.equal(unverifiedAsnLease.body.error, "independent_asn_verification_required");
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
