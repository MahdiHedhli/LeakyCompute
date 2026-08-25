/**
 * I-26: corpus records are minimised, and they expire on silence — measured
 * from the last *successful* probe, never from record creation.
 *
 * The two halves of that sentence fail in opposite directions, so both are
 * asserted as discriminators rather than as smoke tests:
 *
 *   - a record whose creation is ancient but which still answers must survive
 *     a sweep (creation-based expiry would delete it);
 *   - a record created yesterday out of an old listing but silent for 181 days
 *     must be deleted (creation-based expiry would keep it).
 *
 * Also covers I-25's deletion half — an exclusion removes what we already
 * hold — because that path shares the delete machinery.
 */
import assert from "node:assert/strict";
import worker from "../src/index.js";
import {
  recordExposedHost,
  sweepExpiredHosts,
  forgetHosts,
  ingestDiscoveryBatch,
  getCorpusCounts,
  RETENTION_DAYS,
} from "../src/lib/discovery.js";
import {
  check,
  section,
  finish,
  makeKV,
  daysAgo,
  seedRecord,
  readRecord,
  hitKeys,
} from "./_harness.mjs";

const ADMIN = "test-admin-token";

function freshEnv(overrides = {}) {
  return {
    KV: makeKV(),
    ENVIRONMENT: "test",
    ALLOWED_ORIGINS: "https://mahdihedhli.github.io",
    ADMIN_SYNC_TOKEN: ADMIN,
    ...overrides,
  };
}

function adminPost(path, body, token = ADMIN) {
  return new Request(`https://api.test${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Admin-Token": token },
    body: JSON.stringify(body),
  });
}

const ctx = { waitUntil: (p) => p.catch(() => {}) };

/* ------------------------------------------------------------------ */
section("[R1] I-26 expiry is measured from the last successful probe");

{
  const env = freshEnv();
  // Created 400 days ago, answered yesterday. Under a creation-based rule this
  // record is 220 days over the line; under I-26 it is live exposure.
  await seedRecord(env.KV, {
    ip: "198.51.100.1",
    port: 11434,
    stack: "ollama",
    stacks: ["ollama"],
    first_seen: daysAgo(400),
    last_seen: daysAgo(1),
    country_code: "ZZ",
    asn: "AS64496",
  });
  const summary = await sweepExpiredHosts(env);

  await check("a record that keeps answering is never deleted, however old", () => {
    assert.equal(summary.deleted, 0);
    assert.equal(summary.retained, 1);
    assert.ok(hitKeys(env.KV).includes("discovery:hit:198.51.100.1"));
  });
}

{
  const env = freshEnv();
  // Mirror image: first seen yesterday (a fresh row built from an old listing),
  // last contact 181 days ago. Creation-based expiry would keep this forever.
  await seedRecord(env.KV, {
    ip: "198.51.100.2",
    port: 11434,
    stack: "ollama",
    stacks: ["ollama"],
    first_seen: daysAgo(1),
    last_seen: daysAgo(181),
    country_code: "ZZ",
    asn: "AS64496",
  });
  const summary = await sweepExpiredHosts(env);

  await check("a record silent for 181 days is deleted, however recently created", async () => {
    assert.equal(summary.deleted, 1);
    assert.equal(await readRecord(env.KV, "198.51.100.2"), null);
  });

  await check("the deleted host is dropped from the index, not just the key", async () => {
    const index = await env.KV.get("discovery:hits_index", "json");
    assert.deepEqual(index, []);
  });
}

{
  const env = freshEnv();
  await seedRecord(env.KV, {
    ip: "198.51.100.3",
    first_seen: daysAgo(400),
    last_seen: daysAgo(RETENTION_DAYS - 1),
    country_code: "ZZ",
  });
  const summary = await sweepExpiredHosts(env);
  await check(`silent for ${RETENTION_DAYS - 1} days is inside the window`, () => {
    assert.equal(summary.deleted, 0);
    assert.equal(summary.retained, 1);
  });
}

{
  const env = freshEnv();
  await seedRecord(env.KV, {
    ip: "198.51.100.4",
    first_seen: daysAgo(400),
    last_seen: daysAgo(200),
    country_code: "ZZ",
    asn: "AS64496",
    stacks: ["ollama"],
  });
  // A successful probe today. The record was 20 days past due a moment ago.
  await recordExposedHost(env, { ip: "198.51.100.4", port: 11434, stack: "ollama" });
  const stored = await readRecord(env.KV, "198.51.100.4");
  const summary = await sweepExpiredHosts(env);

  await check("a successful probe resets the clock on an overdue record", () => {
    assert.ok(Date.now() - Date.parse(stored.last_seen) < 60000, "last_seen not refreshed");
    assert.equal(summary.deleted, 0, "record was reset by contact and must survive");
  });

  await check("contact does not rewrite first_seen (creation stays creation)", () => {
    assert.ok(
      Date.now() - Date.parse(stored.first_seen) > 300 * 86400000,
      "first_seen must keep the original creation date"
    );
  });
}

{
  const env = freshEnv();
  await seedRecord(env.KV, {
    ip: "198.51.100.5",
    first_seen: daysAgo(400),
    last_seen: daysAgo(200),
    country_code: "ZZ",
  });
  // Counted in an index, not probed. This must NOT look like contact, or an
  // index listing alone would keep a dead host in the corpus forever.
  await recordExposedHost(env, { ip: "198.51.100.5", port: 11434, answered: false });
  const stored = await readRecord(env.KV, "198.51.100.5");
  const summary = await sweepExpiredHosts(env);

  await check("observing a listing (answered:false) does not reset the clock", () => {
    assert.ok(
      Date.now() - Date.parse(stored.last_seen) > 190 * 86400000,
      "answered:false must leave last_seen alone"
    );
    assert.equal(summary.deleted, 1, "a host we only counted must still age out");
  });
}

{
  const env = freshEnv();
  await recordExposedHost(env, { ip: "198.51.100.6", port: 11434, stack: "ollama" });
  await check("every answering probe rewrites the TTL backstop", () => {
    assert.ok(env.KV._ttl.get("discovery:hit:198.51.100.6") >= RETENTION_DAYS * 86400);
  });

  // The TTL is a backstop for the sweep, so it has to fire after it. Set to the
  // same window it always won, and the sweep then found the key already gone —
  // it pruned the index down the orphan branch and never decremented the
  // country/ASN/stack aggregates, so the published counts only ever grew.
  await check("the TTL backstop outlives the retention window, so the sweep wins", () => {
    assert.ok(
      env.KV._ttl.get("discovery:hit:198.51.100.6") > RETENTION_DAYS * 86400,
      "a TTL equal to the window expires the key before the sweep can decrement its buckets"
    );
  });
}

/* ------------------------------------------------------------------ */
section("[R2] I-26 minimised shape: no model lists, job records or page bodies");

// Everything a hostile or over-generous runner might attach. None of it is
// part of the finding "this port answers an unauthenticated read".
const SENTINELS = {
  models: [{ name: "llama3.2:3b", size: 2019393189 }],
  jobs: [{ job_id: "raysubmit_deadbeef", entrypoint: "python train.py" }],
  body: "<html><title>Jupyter Notebook</title></html>",
  page_title: "Jupyter Notebook",
  notebooks: ["secrets.ipynb"],
  city: "Frankfurt",
  org: "Example Hosting GmbH",
  product: "Ollama 0.1.40",
  vulns: [{ id: "CVE-2024-37032" }],
  times_seen: 9,
  headers: { server: "uvicorn" },
};

const ALLOWED_KEYS = new Set([
  "ip",
  "port",
  "ports",
  "stack",
  "stacks",
  "version",
  "first_seen",
  "last_seen",
  "source",
  "country",
  "country_code",
  "asn",
  // Bookkeeping about our own published counters — which country/ASN/stack
  // bucket this record was counted into. It holds no value that is not already
  // in the list above, and the assertion below pins that so it cannot become a
  // side door for content the rest of this section keeps out.
  "counted",
]);

{
  const env = freshEnv();
  await recordExposedHost(env, {
    ip: "198.51.100.10",
    port: 11434,
    stack: "ollama",
    version: "0.6.2",
    country: "Germany",
    country_code: "DE",
    asn: "AS64496",
    source: "shodan:ollama",
    ...SENTINELS,
  });
  const stored = await readRecord(env.KV, "198.51.100.10");

  await check("stored record carries no key outside the retained set", () => {
    const extra = Object.keys(stored).filter((k) => !ALLOWED_KEYS.has(k));
    assert.deepEqual(extra, [], `unexpected retained field(s): ${extra.join(", ")}`);
  });

  await check("no model list, job record or page body survives the write", () => {
    const raw = JSON.stringify(stored);
    for (const needle of [
      "llama3.2",
      "raysubmit",
      "train.py",
      "<html",
      "secrets.ipynb",
      "Frankfurt",
      "Example Hosting",
      "CVE-2024-37032",
      "uvicorn",
    ]) {
      assert.ok(!raw.includes(needle), `record leaked ${needle}`);
    }
  });

  await check("the fields the finding does need are kept", () => {
    assert.equal(stored.version, "0.6.2");
    assert.equal(stored.asn, "AS64496");
    assert.equal(stored.country_code, "DE");
    assert.equal(stored.source, "shodan:ollama");
  });

  await check("the counter bookkeeping carries nothing that is not already retained", () => {
    const flat = JSON.stringify(stored.counted);
    assert.ok(flat.includes("DE") && flat.includes("AS64496"), "expected the counted buckets");
    // Anything in SENTINELS reaching this field would make it a bypass.
    for (const needle of ["llama3.2", "Frankfurt", "Example Hosting", "uvicorn", "0.6.2"]) {
      assert.ok(!flat.includes(needle), `counted leaked ${needle}`);
    }
  });
}

{
  // Same assertion one layer up: the runner's batch is untrusted input too.
  const env = freshEnv();
  await ingestDiscoveryBatch(env, {
    results: [
      {
        ip: "198.51.100.11",
        port: 8265,
        exposed: true,
        stack: "ray",
        version: "2.9.0",
        source: "shodan:ray",
        asn: "AS64497",
        country_code: "US",
        ...SENTINELS,
      },
    ],
    run_meta: { mode: "test" },
  });
  const stored = await readRecord(env.KV, "198.51.100.11");

  await check("ingest drops everything outside the retained set", () => {
    const extra = Object.keys(stored).filter((k) => !ALLOWED_KEYS.has(k));
    assert.deepEqual(extra, [], `unexpected retained field(s): ${extra.join(", ")}`);
    assert.ok(!JSON.stringify(stored).includes("raysubmit"));
    assert.ok(!JSON.stringify(stored).includes("llama3.2"));
  });

  await check("model names survive only as a host-less catalog count", async () => {
    const catalog = await env.KV.get("catalog:validated", "json");
    const row = (catalog.models || []).find((m) => m.model === "llama3.2:3b");
    assert.ok(row, "expected an anonymous catalog entry");
    assert.ok(!JSON.stringify(catalog).includes("198.51.100.11"), "catalog must not name a host");
  });
}

{
  const env = freshEnv();
  await env.KV.put(
    "exclusions:v1",
    JSON.stringify([{ type: "cidr4", value: "198.51.100.0/24", active: true }])
  );
  await ingestDiscoveryBatch(env, {
    // A stale or hostile caller snapshot must not replace the authoritative list.
    exclusions: [],
    results: [{ ip: "198.51.100.12", port: 11434, exposed: true, stack: "ollama" }],
  });

  await check("caller exclusions cannot weaken the authoritative opt-out list", async () => {
    assert.equal(await readRecord(env.KV, "198.51.100.12"), null);
  });
}

{
  const env = freshEnv();
  const get = env.KV.get.bind(env.KV);
  env.KV.get = async (key, type) => {
    if (key === "exclusions:v1") throw new Error("simulated exclusion-store outage");
    return get(key, type);
  };

  await check("admin ingest fails closed when the opt-out list is unreadable", async () => {
    await assert.rejects(
      ingestDiscoveryBatch(env, {
        results: [{ ip: "198.51.100.13", port: 11434, exposed: true, stack: "ollama" }],
      }),
      /simulated exclusion-store outage/
    );
    assert.equal(await readRecord(env.KV, "198.51.100.13"), null);
  });
}

/* ------------------------------------------------------------------ */
section("[R3] deletion actually deletes: aggregates, counts, and failing loud");

{
  const env = freshEnv();
  await recordExposedHost(env, {
    ip: "198.51.100.20",
    port: 11434,
    stack: "ollama",
    country_code: "DE",
    asn: "AS64496",
  });
  const before = await getCorpusCounts(env);
  await seedRecord(env.KV, {
    ...(await readRecord(env.KV, "198.51.100.20")),
    last_seen: daysAgo(365),
  });
  await sweepExpiredHosts(env);

  await check("an expired host leaves the public country/ASN/stack aggregates", async () => {
    const geo = await env.KV.get("stats:by_country", "json");
    const asn = await env.KV.get("stats:by_asn", "json");
    const stack = await env.KV.get("stats:by_stack", "json");
    assert.equal(geo.DE, undefined, "country count still includes a deleted host");
    assert.equal(asn.AS64496, undefined, "ASN count still includes a deleted host");
    assert.equal(stack.ollama, undefined, "stack count still includes a deleted host");
  });

  await check("the re-verified corpus count follows deletion down", async () => {
    assert.equal(before.reverified_hosts, 1);
    const after = await getCorpusCounts(env);
    assert.equal(after.reverified_hosts, 0);
  });
}

{
  const env = freshEnv({ KV: makeKV({ deletable: false }) });
  await seedRecord(env.KV, { ip: "198.51.100.21", first_seen: daysAgo(400), last_seen: daysAgo(400) });
  await check("a store that cannot delete raises instead of reporting 0 deleted", async () => {
    await assert.rejects(() => sweepExpiredHosts(env), /kv_delete_unavailable/);
  });
}

{
  const env = freshEnv();
  await env.KV.put("discovery:hits_index", JSON.stringify(["198.51.100.30", "198.51.100.31"]));
  await seedRecord(env.KV, { ip: "198.51.100.31", first_seen: daysAgo(2), last_seen: daysAgo(2) });
  const summary = await sweepExpiredHosts(env);
  await check("an index entry whose record already aged out is pruned", async () => {
    assert.equal(summary.orphaned, 1);
    assert.deepEqual(await env.KV.get("discovery:hits_index", "json"), ["198.51.100.31"]);
  });
}

/* ------------------------------------------------------------------ */
section("[R4] the retention window can be tightened, never widened");

{
  const env = freshEnv();
  await seedRecord(env.KV, { ip: "198.51.100.40", first_seen: daysAgo(400), last_seen: daysAgo(200) });
  const res = await worker.fetch(
    adminPost("/v1/admin/discovery/sweep", { retention_days: 3650 }),
    env,
    ctx
  );
  const body = await res.json();
  await check("an admin request for a 10-year window is clamped to I-26's ceiling", () => {
    assert.equal(res.status, 200);
    assert.ok(body.retention_days <= RETENTION_DAYS, `got ${body.retention_days}`);
    assert.equal(body.deleted, 1, "the 200-day-silent record must still be deleted");
  });
}

{
  const env = freshEnv({ CORPUS_EXPIRY_DAYS: "3650" });
  await seedRecord(env.KV, { ip: "198.51.100.41", first_seen: daysAgo(400), last_seen: daysAgo(200) });
  const res = await worker.fetch(adminPost("/v1/admin/discovery/sweep", {}), env, ctx);
  const body = await res.json();
  await check("an env var cannot widen the window past I-26 either", () => {
    assert.ok(body.retention_days <= RETENTION_DAYS, `got ${body.retention_days}`);
    assert.equal(body.deleted, 1);
  });
}

{
  const env = freshEnv({ CORPUS_EXPIRY_DAYS: "30" });
  await seedRecord(env.KV, { ip: "198.51.100.42", first_seen: daysAgo(400), last_seen: daysAgo(60) });
  const res = await worker.fetch(adminPost("/v1/admin/discovery/sweep", {}), env, ctx);
  const body = await res.json();
  await check("a deployment may hold records for less time than the ceiling", () => {
    assert.equal(body.retention_days, 30);
    assert.equal(body.deleted, 1);
  });
}

{
  const env = freshEnv();
  const res = await worker.fetch(
    adminPost("/v1/admin/discovery/sweep", {}, "wrong-token"),
    env,
    ctx
  );
  await check("the sweep route is admin-gated", () => assert.equal(res.status, 401));
}

{
  const env = freshEnv({ KV: makeKV({ deletable: false }) });
  await seedRecord(env.KV, { ip: "198.51.100.43", first_seen: daysAgo(400), last_seen: daysAgo(400) });
  const res = await worker.fetch(adminPost("/v1/admin/discovery/sweep", {}), env, ctx);
  const body = await res.json();
  await check("the sweep route reports a store it cannot delete from, not ok:true", () => {
    assert.equal(res.status, 501);
    assert.equal(body.error, "kv_delete_unavailable");
    assert.notEqual(body.ok, true);
  });
}

/* ------------------------------------------------------------------ */
section("[R5] I-25: an exclusion deletes what we already hold");

{
  const env = freshEnv();
  await recordExposedHost(env, {
    ip: "203.0.113.55",
    port: 11434,
    stack: "ollama",
    country_code: "DE",
    asn: "AS64496",
  });
  await recordExposedHost(env, {
    ip: "198.51.100.55",
    port: 11434,
    stack: "ollama",
    country_code: "FR",
    asn: "AS64497",
  });

  const res = await worker.fetch(
    adminPost("/v1/admin/exclusions", { entries: ["203.0.113.0/24"], issue_number: 7 }),
    env,
    ctx
  );
  const body = await res.json();

  await check("the excluded host's record is deleted, not merely hidden", async () => {
    assert.equal(res.status, 200);
    assert.equal(await readRecord(env.KV, "203.0.113.55"), null);
    assert.equal(body.purged.deleted, 1);
  });

  await check("an unrelated host is untouched by someone else's opt-out", async () => {
    assert.ok(await readRecord(env.KV, "198.51.100.55"));
  });

  await check("the response counts deletions without listing the addresses", () => {
    assert.ok(!JSON.stringify(body).includes("203.0.113.55"));
  });
}

{
  const env = freshEnv();
  await recordExposedHost(env, { ip: "203.0.113.56", port: 11434, stack: "ollama" });
  await forgetHosts(env, ["203.0.113.56"]);
  await check("forgetHosts removes the record and its index entry", async () => {
    assert.equal(await readRecord(env.KV, "203.0.113.56"), null);
    assert.deepEqual(await env.KV.get("discovery:hits_index", "json"), []);
  });
}

{
  // A re-filed removal request adds nothing new (addExclusions drops entries it
  // already holds), so purging only what a single request accepted purged
  // nothing on the second attempt — which is the attempt an operator makes
  // precisely because the first one visibly did not work.
  const env = freshEnv();
  await recordExposedHost(env, { ip: "203.0.113.57", port: 11434, stack: "ollama" });
  await worker.fetch(adminPost("/v1/admin/exclusions", { entries: ["203.0.113.0/24"] }), env, ctx);
  // Put the record back the way a runner with a stale list would.
  await recordExposedHost(env, { ip: "203.0.113.57", port: 11434, stack: "ollama" });

  const res = await worker.fetch(
    adminPost("/v1/admin/exclusions", { entries: ["203.0.113.0/24"] }),
    env,
    ctx
  );
  const body = await res.json();
  await check("re-filing a removal request purges again, not only the first time", async () => {
    assert.deepEqual(body.accepted, [], "the rule was already stored");
    assert.equal(body.purged.deleted, 1, "an already-stored exclusion must still delete records");
    assert.equal(await readRecord(env.KV, "203.0.113.57"), null);
  });
}

{
  const env = freshEnv();
  await worker.fetch(adminPost("/v1/admin/exclusions", { entries: ["203.0.113.0/24"] }), env, ctx);
  const res = await worker.fetch(
    adminPost("/v1/admin/discovery/ingest", {
      results: [
        { ip: "203.0.113.58", port: 11434, exposed: true, stack: "ollama" },
        { ip: "198.51.100.58", port: 11434, exposed: true, stack: "ollama" },
      ],
    }),
    env,
    ctx
  );
  const body = await res.json();
  await check("an ingest cannot write back a host that is excluded (I-25)", async () => {
    assert.equal(body.refused_excluded, 1);
    assert.equal(await readRecord(env.KV, "203.0.113.58"), null);
    assert.ok(await readRecord(env.KV, "198.51.100.58"), "an unrelated host still ingests");
  });
}

/* ------------------------------------------------------------------ */
section("[R6] the public aggregates track the corpus they claim to describe");

{
  // Verified end to end in the original report: a self-check writes a host with
  // no geo (bucket "ZZ"), a discovery ingest later enriches it to DE without
  // re-keying, and expiring it decremented DE — deleting a *different*, live
  // host's count and stranding the ZZ entry forever.
  const env = freshEnv();
  await recordExposedHost(env, { ip: "198.51.100.60", port: 11434, stack: "ollama" });
  await recordExposedHost(env, {
    ip: "198.51.100.61",
    port: 11434,
    stack: "ollama",
    country_code: "DE",
  });
  await recordExposedHost(env, {
    ip: "198.51.100.60",
    port: 11434,
    stack: "ollama",
    country_code: "DE",
  });

  await check("enrichment moves a host between country buckets instead of duplicating it", async () => {
    const geo = await env.KV.get("stats:by_country", "json");
    assert.equal(geo.DE, 2, `expected both hosts under DE, got ${JSON.stringify(geo)}`);
    assert.equal(geo.ZZ, undefined, "the pre-enrichment bucket must be given back");
  });

  await forgetHosts(env, ["198.51.100.60"]);
  await check("deleting the enriched host does not steal the other host's count", async () => {
    const geo = await env.KV.get("stats:by_country", "json");
    assert.equal(geo.DE, 1, `live host lost its count: ${JSON.stringify(geo)}`);
    assert.equal(geo.ZZ, undefined, "a phantom bucket was stranded");
  });
}

{
  // stats:corpus is newer than the corpus it counts. Gating the increment on
  // "first write" meant every pre-existing record stayed uncounted forever
  // while forgetRecord still decremented for it, so the headline re-verified
  // number sat at 0 no matter how many hosts answered.
  const env = freshEnv();
  for (const n of [70, 71, 72, 73, 74]) {
    await seedRecord(env.KV, {
      ip: `198.51.100.${n}`,
      port: 11434,
      stack: "ollama",
      stacks: ["ollama"],
      first_seen: daysAgo(300),
      last_seen: daysAgo(20),
      country_code: "ZZ",
    });
  }
  for (const n of [80, 81, 82]) {
    await seedRecord(env.KV, {
      ip: `198.51.100.${n}`,
      port: 11434,
      first_seen: daysAgo(400),
      last_seen: daysAgo(300),
      country_code: "ZZ",
    });
  }
  await recordExposedHost(env, { ip: "198.51.100.90", port: 11434, stack: "ollama" });
  await recordExposedHost(env, { ip: "198.51.100.91", port: 11434, stack: "ollama" });
  for (const n of [70, 71, 72, 73, 74]) {
    await recordExposedHost(env, { ip: `198.51.100.${n}`, port: 11434, stack: "ollama" });
  }
  await sweepExpiredHosts(env);

  await check("re-verifying a legacy record counts it in, rather than only out", async () => {
    const counts = await getCorpusCounts(env);
    assert.equal(
      counts.reverified_hosts,
      7,
      `5 healed legacy hosts + 2 new ones should be counted, got ${counts.reverified_hosts}`
    );
    assert.ok(counts.last_reverified_at, "a re-verification must stamp last_reverified_at");
  });
}

{
  const env = freshEnv();
  await recordExposedHost(env, { ip: "198.51.100.95", port: 11434, stack: "ollama" });
  const first = await getCorpusCounts(env);
  await recordExposedHost(env, { ip: "198.51.100.95", port: 11434, stack: "ollama" });
  await check("re-probing the same host does not count it twice", async () => {
    assert.equal(first.reverified_hosts, 1);
    assert.equal((await getCorpusCounts(env)).reverified_hosts, 1);
  });
}

{
  // A listing we merely counted is not a re-verification, and the country chart
  // says "re-verified in the last 180 days" — so it must not enter that either.
  const env = freshEnv();
  await recordExposedHost(env, {
    ip: "198.51.100.96",
    port: 11434,
    stack: "ollama",
    country_code: "FR",
    answered: false,
  });
  await check("a host we only observed in an index enters no public aggregate", async () => {
    assert.equal((await getCorpusCounts(env)).reverified_hosts, 0);
    const geo = (await env.KV.get("stats:by_country", "json")) || {};
    assert.equal(geo.FR, undefined, "an unprobed listing was counted as re-verified exposure");
  });
}

/* ------------------------------------------------------------------ */
section("[R7] spec §4: the three numbers are all actually produced");

{
  const env = freshEnv();
  await worker.fetch(
    adminPost("/v1/admin/discovery/ingest", {
      results: [
        {
          ip: "198.51.100.100",
          port: 11434,
          exposed: true,
          stack: "ollama",
          // The runner's only version source for a host it did not fingerprint.
          product: "Ollama 0.1.40",
        },
      ],
      run_meta: { indexed_observed: 1732, observed_source: "public index records" },
    }),
    env,
    ctx
  );
  const stats = await (await worker.fetch(new Request("https://api.test/v1/stats"), env, ctx)).json();

  await check("indexed_observed reaches the public payload instead of a hard zero", () => {
    assert.equal(stats.indexed_observed.hosts, 1732);
    assert.ok(stats.reverified.hosts >= 1);
    assert.notEqual(stats.indexed_observed.hosts, stats.archive_snapshot.hosts);
  });

  await check("a version is retained from the index banner, not left null", async () => {
    const rec = await readRecord(env.KV, "198.51.100.100");
    assert.equal(rec.version, "0.1.40", "no version means no OSV lookup downstream");
    assert.ok(!JSON.stringify(rec).includes("Ollama 0.1.40"), "the banner itself is not retained");
  });
}

/* ------------------------------------------------------------------ */
section("[R8] I-24: the re-probe clock covers hosts that did not answer");

{
  const env = freshEnv();
  await worker.fetch(
    adminPost("/v1/admin/discovery/ingest", {
      results: [
        { ip: "198.51.100.110", port: 11434, exposed: true, stack: "ollama" },
        // Probed, did not answer: no record is written for it (I-26), which is
        // exactly why the exposure store cannot be the interval clock.
        { ip: "198.51.100.111", port: 11434, exposed: false, stack: "ollama" },
      ],
    }),
    env,
    ctx
  );
  const res = await worker.fetch(
    new Request("https://api.test/v1/admin/discovery/clock", {
      headers: { "X-Admin-Token": ADMIN },
    }),
    env,
    ctx
  );
  const body = await res.json();

  await check("a host that did not answer still lands in the probe clock", async () => {
    assert.equal(await readRecord(env.KV, "198.51.100.111"), null, "no record, by I-26");
    assert.ok(body.attempts["198.51.100.111"], "a silent host must still hold off the next probe");
    assert.ok(body.attempts["198.51.100.110"]);
  });

  await check("the clock is admin-gated: it is a list of addresses (I-14)", async () => {
    const anon = await worker.fetch(
      new Request("https://api.test/v1/admin/discovery/clock"),
      env,
      ctx
    );
    assert.equal(anon.status, 401);
  });

  await check("an exclusion clears the clock entry too", async () => {
    await worker.fetch(
      adminPost("/v1/admin/exclusions", { entries: ["198.51.100.111"] }),
      env,
      ctx
    );
    const after = await (
      await worker.fetch(
        new Request("https://api.test/v1/admin/discovery/clock", {
          headers: { "X-Admin-Token": ADMIN },
        }),
        env,
        ctx
      )
    ).json();
    assert.equal(after.attempts["198.51.100.111"], undefined);
  });
}

/* ------------------------------------------------------------------ */
section("[R9] the sweep is bounded per invocation and resumes where it stopped");

{
  const env = freshEnv();
  for (let n = 0; n < 12; n++) {
    await seedRecord(env.KV, {
      ip: `198.51.100.${120 + n}`,
      port: 11434,
      first_seen: daysAgo(400),
      last_seen: daysAgo(300),
      country_code: "ZZ",
    });
  }
  const first = await sweepExpiredHosts(env, { maxScan: 5 });

  await check("a sweep stops inside its KV budget rather than throwing mid-loop", () => {
    assert.equal(first.scanned, 5);
    assert.equal(first.deleted, 5);
    assert.equal(first.complete, false);
    assert.equal(first.remaining, 7);
  });

  await check("the index agrees with the keys that survived, even part-way", async () => {
    const index = await env.KV.get("discovery:hits_index", "json");
    assert.equal(index.length, 7, `index must drop what was deleted: ${JSON.stringify(index)}`);
    for (const ip of index) assert.ok(await readRecord(env.KV, ip), `${ip} deleted but still listed`);
  });

  let guard = 0;
  let summary = first;
  while (!summary.complete && guard++ < 10) {
    summary = await sweepExpiredHosts(env, { maxScan: 5 });
  }
  await check("successive runs finish the corpus", async () => {
    assert.equal(summary.complete, true);
    assert.deepEqual(await env.KV.get("discovery:hits_index", "json"), []);
    assert.deepEqual(hitKeys(env.KV), []);
  });
}

/* ------------------------------------------------------------------ */
section("KV write budget: refuse before the first write, not partway through");

{
  const env = await freshEnv();
  // Park the day's counter just under the ceiling.
  await env.KV.put("kv:puts:" + new Date().toISOString().slice(0, 10), "895");

  const before = env.KV._store ? env.KV._store.size : null;
  const res = await worker.fetch(
    new Request("https://api.test/v1/admin/discovery/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Token": ADMIN,
                 "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        results: Array.from({ length: 100 }, (_, i) => ({
          ip: `203.0.113.${i}`, port: 11434, exposed: true, stack: "ollama",
          source: "shodan:ollama",
        })),
      }),
    }),
    env,
    ctx
  );
  const body = await res.json();

  await check("a batch that would cross the ceiling is refused", async () => {
    assert.equal(res.status, 429);
    assert.equal(body.error, "kv_write_budget_exhausted");
  });

  await check("the refusal names what it would have cost", async () => {
    assert.ok(body.estimated >= 100, JSON.stringify(body));
    assert.ok(body.remaining < body.estimated, JSON.stringify(body));
  });

  await check("nothing was written — no partial corpus", async () => {
    const keys = [...(env.KV._store?.keys() || [])].filter((k) =>
      k.startsWith("discovery:hit:")
    );
    assert.deepEqual(keys, [], `expected no records written, got ${keys.length}`);
  });
}

{
  const env = await freshEnv();
  const res = await worker.fetch(
    new Request("https://api.test/v1/admin/discovery/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Token": ADMIN,
                 "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        results: Array.from({ length: 40 }, (_, i) => ({
          ip: `203.0.113.${i}`, port: 11434, exposed: true, stack: "ollama",
          country_code: ["DE", "US"][i % 2], asn: "AS6449" + (i % 3),
          source: "shodan:ollama",
        })),
      }),
    }),
    env,
    ctx
  );
  const body = await res.json();
  await check("a normal batch stays near one put per host", async () => {
    assert.equal(res.status, 200);
    // Pre-batching this was ~6 per host. The aggregate flush is a fixed cost.
    assert.ok(body.kv_puts <= 40 + 10, `kv_puts=${body.kv_puts} for 40 hosts`);
  });
}

/* ------------------------------------------------------------------ */
// reverified_hosts read 478 against 629 real records. It increments once per
// record, gated on a marker stored on that record and set in the same breath as
// the increment — so when a write batch fails, the record keeps the marker and
// the counter never gets its increment back. Drift is one-directional and, until
// this existed, permanent.
section("aggregates can be recounted from the records themselves");

{
  const { recordExposedHost, reconcileCorpusCounts, getCorpusCounts } =
    await import("../src/lib/discovery.js");
  const env = await freshEnv();

  for (let i = 0; i < 12; i++) {
    await recordExposedHost(env, {
      ip: `203.0.113.${i}`, port: 11434, stack: "ollama",
      country_code: i % 2 ? "DE" : "US", asn: "AS6449" + (i % 3),
      source: "shodan:ollama",
    });
  }

  // Simulate exactly the failure: records exist, the counter lost its increments.
  const corpus = await env.KV.get("stats:corpus", "json");
  await env.KV.put("stats:corpus", JSON.stringify({ ...corpus, reverified_hosts: 4 }));

  const before = await getCorpusCounts(env);
  await check("drift is present before reconciling", async () => {
    assert.equal(before.reverified_hosts, 4);
  });

  const partial = await reconcileCorpusCounts(env, { limit: 5 });
  await check("a partial recount refuses instead of overwriting complete aggregates", async () => {
    assert.equal(partial.ok, false);
    assert.equal(partial.reason, "corpus_exceeds_reconcile_limit");
    assert.equal((await getCorpusCounts(env)).reverified_hosts, 4);
  });

  const res = await reconcileCorpusCounts(env);

  await check("recount matches the actual record count", async () => {
    assert.equal(res.records, 12);
    assert.equal(res.reverified_after, 12);
    assert.equal(res.drift, 8);
  });

  await check("the published counter is corrected", async () => {
    const after = await getCorpusCounts(env);
    assert.equal(after.reverified_hosts, 12);
  });

  await check("country and stack maps are rebuilt from the records too", async () => {
    const geo = await env.KV.get("stats:by_country", "json");
    assert.equal(geo.DE + geo.US, 12);
    const stack = await env.KV.get("stats:by_stack", "json");
    assert.equal(stack.ollama, 12);
  });

  await check("reconciling twice changes nothing — it is idempotent", async () => {
    const again = await reconcileCorpusCounts(env);
    assert.equal(again.records, 12);
    assert.equal(again.drift, 0);
  });
}

finish();
