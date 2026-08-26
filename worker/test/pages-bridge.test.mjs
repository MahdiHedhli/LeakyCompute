import assert from "node:assert/strict";
import { onRequest } from "../../functions/v1/research/[[path]].js";

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

const originalFetch = globalThis.fetch;
const calls = [];
globalThis.fetch = async (url, init) => {
  calls.push({ url: String(url), init });
  return new Response("ok", {
    status: 200,
    headers: {
      "Set-Cookie": "secret=1",
      "Access-Control-Allow-Origin": "*",
    },
  });
};

const context = (path, { method = "GET", jwt = "signed", headers = {} } = {}) => ({
  request: new Request(`https://lab.test/v1/research/${Array.isArray(path) ? path.join("/") : path}`, {
    method,
    headers: {
      ...(jwt ? { "Cf-Access-Jwt-Assertion": jwt } : {}),
      ...headers,
    },
  }),
  params: { path },
});

console.log("\n[B1] Pages research bridge is a narrow identity-forwarding hop");

await check("missing Access assertion fails before forwarding", async () => {
  const before = calls.length;
  const res = await onRequest(context(["lab", "catalog"], { jwt: null }));
  assert.equal(res.status, 403);
  assert.equal(calls.length, before);
});

await check("non-GET methods fail before forwarding", async () => {
  const before = calls.length;
  const res = await onRequest(context(["lab", "catalog"], { method: "POST" }));
  assert.equal(res.status, 405);
  assert.equal(calls.length, before);
});

await check("encoded traversal cannot normalize into an admin route", async () => {
  const before = calls.length;
  const res = await onRequest(context(["%2e%2e", "admin", "discovery", "hits"]));
  assert.equal(res.status, 404);
  assert.equal(calls.length, before);
});

await check("post-login document navigation to /me returns to the lab shell", async () => {
  const before = calls.length;
  const res = await onRequest(context("me", {
    headers: {
      Accept: "text/html,application/xhtml+xml",
      "Sec-Fetch-Mode": "navigate",
    },
  }));
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "https://lab.test/");
  assert.match(res.headers.get("cache-control") || "", /no-store/);
  assert.equal(calls.length, before);
});

await check("application fetch to /me still reaches the fixed upstream", async () => {
  const res = await onRequest(context("me", {
    headers: { Accept: "application/json" },
  }));
  assert.equal(res.status, 200);
  assert.equal(calls.at(-1).url, "https://api.leakycompute.mahdihedhli.com/v1/research/me");
});

await check("known route forwards only allowlisted headers to the fixed upstream", async () => {
  const res = await onRequest(context(["lab", "catalog"], {
    headers: {
      Accept: "application/json",
      "X-Admin-Token": "must-not-forward",
      "X-GitHub-Login": "must-not-forward",
    },
  }));
  assert.equal(res.status, 200);
  const call = calls.at(-1);
  assert.equal(call.url, "https://api.leakycompute.mahdihedhli.com/v1/research/lab/catalog");
  assert.equal(call.init.method, "GET");
  assert.equal(call.init.redirect, "manual");
  assert.equal(call.init.headers.get("cf-access-jwt-assertion"), "signed");
  assert.equal(call.init.headers.get("x-admin-token"), null);
  assert.equal(call.init.headers.get("x-github-login"), null);
  assert.equal(res.headers.get("set-cookie"), null);
  assert.equal(res.headers.get("access-control-allow-origin"), null);
  assert.match(res.headers.get("cache-control") || "", /no-store/);
});

globalThis.fetch = originalFetch;

if (failures) process.exit(1);
console.log("\npages-bridge tests passed");
