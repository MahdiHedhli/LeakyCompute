/**
 * I-25 — opt-out is honoured before the probe, not after.
 *
 * The assertion that matters most is ordering: the exclusion must be checked
 * before any request is emitted at a target. A test that only checks the
 * response body would pass even if we probed first and suppressed the result.
 */

import assert from "node:assert/strict";
import {
  parseExclusionEntry,
  isExcluded,
  isBroad,
  addExclusions,
  loadExclusions,
} from "../src/lib/exclusions.js";

let failures = 0;
function ok(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}
async function okAsync(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

function fakeKV() {
  const store = new Map();
  return {
    store,
    async get(k, type) {
      const v = store.get(k);
      if (v == null) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(k, v) {
      store.set(k, v);
    },
    async delete(k) {
      store.delete(k);
    },
  };
}

console.log("\n[1] entry parsing");

ok("plain IPv4 becomes a /32", () => {
  assert.deepEqual(parseExclusionEntry("203.0.113.7"), {
    type: "cidr4",
    value: "203.0.113.7/32",
  });
});

ok("IPv4 CIDR preserved", () => {
  assert.deepEqual(parseExclusionEntry("203.0.113.0/24"), {
    type: "cidr4",
    value: "203.0.113.0/24",
  });
});

ok("ASN accepted in every spelling", () => {
  for (const s of ["AS64496", "as64496", "64496"]) {
    assert.deepEqual(parseExclusionEntry(s), { type: "asn", value: "AS64496" });
  }
});

ok("IPv6 and IPv6 CIDR accepted", () => {
  assert.equal(parseExclusionEntry("2001:db8::1").type, "cidr6");
  assert.equal(parseExclusionEntry("2001:db8::/32").value, "2001:db8::/32");
});

ok("garbage is rejected, not stored as a rule that never fires", () => {
  for (const s of ["", "not-an-ip", "999.1.1.1", "203.0.113.0/33", "2001:db8::/200"]) {
    assert.equal(parseExclusionEntry(s), null, `expected null for ${s!== "" ? s : "(empty)"}`);
  }
});

console.log("\n[2] matching");

const rules = [
  { type: "cidr4", value: "203.0.113.0/24", active: true },
  { type: "asn", value: "AS64496", active: true },
  { type: "cidr6", value: "2001:db8::/32", active: true },
];

ok("address inside an excluded CIDR matches", () => {
  assert.equal(isExcluded(rules, { ip: "203.0.113.55" }), true);
});

ok("address outside it does not", () => {
  assert.equal(isExcluded(rules, { ip: "198.51.100.55" }), false);
});

ok("ASN match works independently of address", () => {
  assert.equal(isExcluded(rules, { ip: "198.51.100.55", asn: "AS64496" }), true);
  assert.equal(isExcluded(rules, { ip: "198.51.100.55", asn: "64496" }), true);
});

ok("IPv6 prefix match works", () => {
  assert.equal(isExcluded(rules, { ip: "2001:db8:dead::1" }), true);
  assert.equal(isExcluded(rules, { ip: "2001:dbf::1" }), false);
});

ok("v4 rule never matches a v6 target or vice versa", () => {
  assert.equal(isExcluded([rules[0]], { ip: "2001:db8::1" }), false);
  assert.equal(isExcluded([rules[2]], { ip: "203.0.113.55" }), false);
});

ok("inactive rules are ignored", () => {
  const off = [{ type: "cidr4", value: "203.0.113.0/24", active: false }];
  assert.equal(isExcluded(off, { ip: "203.0.113.55" }), false);
});

ok("empty list excludes nothing", () => {
  assert.equal(isExcluded([], { ip: "203.0.113.55" }), false);
});

console.log("\n[3] auto-honour bound (anti-griefing)");

ok("0.0.0.0/0 is classified broad", () => {
  assert.equal(isBroad(parseExclusionEntry("0.0.0.0/0")), true);
});

ok("a /24 is not broad", () => {
  assert.equal(isBroad(parseExclusionEntry("203.0.113.0/24")), false);
});

ok("a whole ASN is always auto-honoured", () => {
  assert.equal(isBroad(parseExclusionEntry("AS64496")), false);
});

await okAsync("broad entry is held, not silently accepted or dropped", async () => {
  const env = { KV: fakeKV() };
  const r = await addExclusions(env, ["0.0.0.0/0"], {});
  assert.equal(r.accepted.length, 0, "must not auto-apply");
  assert.equal(r.held.length, 1, "must be held for review");
  assert.equal(isExcluded(await loadExclusions(env), { ip: "8.8.8.8" }), false);
});

await okAsync("maintainer approval lets a broad entry through", async () => {
  const env = { KV: fakeKV() };
  const r = await addExclusions(env, ["0.0.0.0/0"], { allowBroad: true });
  assert.equal(r.accepted.length, 1);
  assert.equal(isExcluded(await loadExclusions(env), { ip: "8.8.8.8" }), true);
});

console.log("\n[4] storage");

await okAsync("unparseable input is reported back, never assumed excluded", async () => {
  const env = { KV: fakeKV() };
  const r = await addExclusions(env, ["203.0.113.0/24", "oops"], {});
  assert.equal(r.accepted.length, 1);
  assert.equal(r.rejected.length, 1);
  assert.equal(r.rejected[0].input, "oops");
});

await okAsync("duplicate submissions do not stack", async () => {
  const env = { KV: fakeKV() };
  await addExclusions(env, ["203.0.113.0/24"], {});
  await addExclusions(env, ["203.0.113.0/24"], {});
  assert.equal((await loadExclusions(env)).length, 1);
});

await okAsync("adding never removes an existing exclusion", async () => {
  const env = { KV: fakeKV() };
  await addExclusions(env, ["203.0.113.0/24"], {});
  await addExclusions(env, ["198.51.100.0/24"], {});
  const list = await loadExclusions(env);
  assert.equal(list.length, 2);
  assert.equal(isExcluded(list, { ip: "203.0.113.9" }), true);
});

console.log(
  failures ? `\nexclusion tests FAILED (${failures})\n` : "\nexclusion tests passed\n"
);
process.exit(failures ? 1 : 0);
