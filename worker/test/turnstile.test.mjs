import assert from "node:assert/strict";
import { verifyTurnstile } from "../src/lib/turnstile.js";

const originalFetch = globalThis.fetch;
const env = {
  ENVIRONMENT: "production",
  TURNSTILE_SECRET_KEY: "test-secret",
  TURNSTILE_EXPECTED_HOSTNAME: "leakycompute.example.test",
};

try {
  let submitted;
  globalThis.fetch = async (_url, init) => {
    submitted = new URLSearchParams(String(init.body));
    return new Response(JSON.stringify({
      success: true,
      hostname: "leakycompute.example.test",
      action: "hosted_self_check",
    }), { headers: { "content-type": "application/json" } });
  };

  const valid = await verifyTurnstile(env, "single-use-token");
  assert.equal(valid.ok, true);
  assert.equal(submitted.get("secret"), "test-secret");
  assert.equal(submitted.get("response"), "single-use-token");
  assert.equal(
    submitted.has("remoteip"),
    false,
    "the optional IP hint must not make browser and Worker identity brittle"
  );

  globalThis.fetch = async () => new Response(JSON.stringify({
    success: true,
    hostname: "other.example.test",
    action: "hosted_self_check",
  }));
  assert.equal((await verifyTurnstile(env, "token")).error, "turnstile_hostname_mismatch");

  globalThis.fetch = async () => new Response(JSON.stringify({
    success: true,
    hostname: "leakycompute.example.test",
    action: "other_action",
  }));
  assert.equal((await verifyTurnstile(env, "token")).error, "turnstile_action_mismatch");

  globalThis.fetch = async () => new Response(JSON.stringify({
    success: false,
    "error-codes": ["timeout-or-duplicate"],
  }));
  const rejected = await verifyTurnstile(env, "token");
  assert.equal(rejected.ok, false);
  assert.equal(rejected.error, "turnstile_rejected");

  assert.equal(
    (await verifyTurnstile({ ENVIRONMENT: "production" }, "token")).error,
    "turnstile_not_configured"
  );
  assert.equal(
    (await verifyTurnstile({ ...env, TURNSTILE_EXPECTED_HOSTNAME: "" }, "token")).error,
    "turnstile_not_configured"
  );

  console.log("turnstile tests passed (exact hostname/action, single-use token, no IP hint)");
} finally {
  globalThis.fetch = originalFetch;
}
