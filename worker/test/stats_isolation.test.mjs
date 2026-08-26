/**
 * Public stats must not be usable as an unauthenticated Workers KV read
 * amplifier. Production caching is configured in wrangler.toml; these route
 * tests prove every path that reaches KV first crosses the edge limiter.
 */
import fs from "node:fs";
import assert from "node:assert/strict";
import worker from "../src/index.js";
import { check, section, finish, makeKV } from "./_harness.mjs";

const ctx = { waitUntil: (p) => p.catch(() => {}) };

function instrumentedKV() {
  const kv = makeKV();
  let reads = 0;
  const get = kv.get.bind(kv);
  kv.get = async (...args) => {
    reads++;
    return get(...args);
  };
  kv.reads = () => reads;
  return kv;
}

function limiter(result = { success: true }) {
  const keys = [];
  return {
    keys,
    async limit({ key }) {
      keys.push(key);
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

function productionEnv(rateLimiter) {
  return {
    KV: instrumentedKV(),
    ENVIRONMENT: "production",
    STATS_RATE_LIMITER: rateLimiter,
    SNAPSHOT_HOSTS: "19348",
    SNAPSHOT_MODELS: "1864",
  };
}

section("[S1] canonical public stats are cacheable as one representation");

{
  const edge = limiter();
  const env = productionEnv(edge);
  const res = await worker.fetch(
    new Request("https://api.test/v1/stats", {
      headers: { Origin: "https://attacker-controlled.example" },
    }),
    env,
    ctx
  );

  await check("a permitted cold miss reaches KV only after the edge limiter", () => {
    assert.equal(res.status, 200);
    assert.deepEqual(edge.keys, ["public-stats"]);
    assert.ok(env.KV.reads() > 0);
  });
  await check("stats have one wildcard-CORS cache variant", () => {
    assert.equal(res.headers.get("Access-Control-Allow-Origin"), "*");
    assert.equal(res.headers.get("Access-Control-Allow-Credentials"), null);
    assert.equal(res.headers.get("Vary"), null);
  });
  await check("browser and edge cache lifetimes are explicit", () => {
    assert.equal(res.headers.get("Cache-Control"), "public, max-age=30");
    assert.equal(
      res.headers.get("Cloudflare-CDN-Cache-Control"),
      "public, max-age=60"
    );
    assert.equal(res.headers.get("Cache-Tag"), "leakycompute-stats");
  });
}

section("[S2] no rejected or unprotected request can read stats KV");

{
  const edge = limiter({ success: false });
  const env = productionEnv(edge);
  const res = await worker.fetch(new Request("https://api.test/v1/stats"), env, ctx);
  const body = await res.json();

  await check("edge denial is a 429 before the first KV read", () => {
    assert.equal(res.status, 429);
    assert.equal(body.error, "rate_limited");
    assert.equal(body.scope, "public_stats");
    assert.equal(res.headers.get("Retry-After"), "60");
    assert.equal(res.headers.get("Cache-Control"), "no-store");
    assert.equal(env.KV.reads(), 0);
  });
}

for (const suffix of ["?cache_bust=1", "/"]) {
  const edge = limiter();
  const env = productionEnv(edge);
  const res = await worker.fetch(
    new Request(`https://api.test/v1/stats${suffix}`),
    env,
    ctx
  );

  await check(`${suffix} is refused before the limiter and KV`, () => {
    assert.equal(res.status, 400);
    assert.deepEqual(edge.keys, []);
    assert.equal(env.KV.reads(), 0);
    assert.equal(res.headers.get("Cache-Control"), "no-store");
  });
}

{
  const env = productionEnv(undefined);
  const res = await worker.fetch(new Request("https://api.test/v1/stats"), env, ctx);
  await check("a missing production binding fails closed before KV", async () => {
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error, "stats_temporarily_unavailable");
    assert.equal(env.KV.reads(), 0);
  });
}

{
  const env = productionEnv(limiter(new Error("edge unavailable")));
  const res = await worker.fetch(new Request("https://api.test/v1/stats"), env, ctx);
  await check("an edge-limiter error fails closed before KV", () => {
    assert.equal(res.status, 503);
    assert.equal(env.KV.reads(), 0);
  });
}

section("[S3] production configuration provides the two isolation layers");

{
  const config = fs.readFileSync(new URL("../../wrangler.toml", import.meta.url), "utf8");
  await check("Workers Caching is enabled before Worker invocation", () => {
    assert.match(config, /\[cache\]\s+enabled\s*=\s*true/);
  });
  await check("the stats limiter binding has a one-minute edge budget", () => {
    assert.match(config, /name\s*=\s*"STATS_RATE_LIMITER"/);
    assert.match(config, /\[ratelimits\.simple\]\s+limit\s*=\s*60\s+period\s*=\s*60/);
  });
}

finish();
