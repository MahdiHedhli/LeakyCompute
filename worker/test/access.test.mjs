import assert from "node:assert/strict";
import { resolveResearcher } from "../src/lib/access.js";

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

const enc = new TextEncoder();
const b64url = (input) => Buffer.from(input)
  .toString("base64")
  .replace(/=/g, "")
  .replace(/\+/g, "-")
  .replace(/\//g, "_");

const pair = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"]
);
const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
publicJwk.kid = "test-key";
publicJwk.alg = "RS256";
publicJwk.use = "sig";

const team = "security-test.cloudflareaccess.com";
const aud = "test-audience";
const now = Math.floor(Date.now() / 1000);

async function jwt(payload, header = { alg: "RS256", typ: "JWT", kid: "test-key" }) {
  const head = b64url(JSON.stringify(header));
  const body = b64url(JSON.stringify(payload));
  const signed = `${head}.${body}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    pair.privateKey,
    enc.encode(signed)
  );
  return `${signed}.${b64url(new Uint8Array(signature))}`;
}

const validPayload = {
  iss: `https://${team}`,
  aud,
  type: "app",
  exp: now + 300,
  iat: now - 5,
  nbf: now - 5,
  sub: "stable-subject",
  email: "approved@example.com",
  preferred_username: "mutable-name",
  nickname: "another-display-name",
};

const originalFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  assert.equal(String(url), `https://${team}/cdn-cgi/access/certs`);
  return Response.json({ keys: [publicJwk] });
};

const request = (token, extra = {}) => new Request("https://api.test/v1/research/me", {
  headers: {
    "Cf-Access-Jwt-Assertion": token,
    "X-GitHub-Login": "spoofed-approved-user",
    ...extra,
  },
});
const env = {
  ENVIRONMENT: "production",
  ACCESS_TEAM_DOMAIN_SECRET: team,
  ACCESS_APP_AUD: aud,
};

console.log("\n[A1] Cloudflare Access identity is cryptographically bound and exact");

await check("valid Access app token resolves exact verified email only", async () => {
  const identity = await resolveResearcher(request(await jwt(validPayload)), env);
  assert.ok(identity);
  assert.deepEqual(identity.candidates, ["approved@example.com"]);
  assert.equal(identity.login, "approved@example.com");
});

await check("caller identity header and mutable signed display claims are ignored", async () => {
  const identity = await resolveResearcher(request(await jwt(validPayload)), env);
  assert.ok(!identity.candidates.includes("spoofed-approved-user"));
  assert.ok(!identity.candidates.includes("mutable-name"));
  assert.ok(!identity.candidates.includes("another-display-name"));
  assert.ok(!identity.candidates.includes("approved"));
});

await check("payload tampering without a new signature is rejected", async () => {
  const token = await jwt(validPayload);
  const parts = token.split(".");
  parts[1] = b64url(JSON.stringify({ ...validPayload, email: "attacker@example.com" }));
  assert.equal(await resolveResearcher(request(parts.join(".")), env), null);
});

for (const [name, payload] of [
  ["expired", { ...validPayload, exp: now - 1 }],
  ["wrong issuer", { ...validPayload, iss: "https://attacker.example" }],
  ["wrong token type", { ...validPayload, type: "service" }],
]) {
  await check(`${name} token is rejected`, async () => {
    assert.equal(await resolveResearcher(request(await jwt(payload)), env), null);
  });
}

await check("unknown signing key id is rejected without fallback", async () => {
  const token = await jwt(validPayload, { alg: "RS256", typ: "JWT", kid: "unknown" });
  assert.equal(await resolveResearcher(request(token), env), null);
});

globalThis.fetch = originalFetch;

if (failures) process.exit(1);
console.log("\naccess tests passed");
