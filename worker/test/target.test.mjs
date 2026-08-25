/**
 * Public target-boundary tests. These are deliberately table-driven because a
 * single forgotten special-purpose prefix turns /v1/check into an SSRF path.
 */
import assert from "node:assert/strict";
import { isPrivateOrLocal, validateTarget } from "../src/lib/check.js";

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (error) {
    failures++;
    console.log(`  FAIL ${name}\n       ${error.message}`);
  }
}

console.log("\n[T1] canonical public IP literals are accepted");
for (const target of [
  "8.8.8.8",
  "93.184.216.34",
  "2606:4700:4700::1111",
  "2001:4860:4860::8888",
  "[2606:4700:4700::1111]",
]) {
  check(`${target} is a public IP literal`, () => {
    const result = validateTarget(target);
    assert.equal(result.ok, true);
    assert.equal(result.kind, "ip");
    assert.equal(isPrivateOrLocal(result.host), false);
  });
}

console.log("\n[T2] every IPv4 special-purpose class fails closed");
for (const target of [
  "0.0.0.1",
  "10.0.0.1",
  "100.64.0.1",
  "127.0.0.1",
  "169.254.169.254",
  "172.16.0.1",
  "192.0.0.9",
  "192.0.2.1",
  "192.31.196.1",
  "192.52.193.1",
  "192.88.99.1",
  "192.168.0.1",
  "192.175.48.1",
  "198.18.0.1",
  "198.51.100.1",
  "203.0.113.1",
  "224.0.0.1",
  "239.255.255.250",
  "240.0.0.1",
  "255.255.255.255",
]) {
  check(`${target} is rejected as non-public`, () => {
    assert.equal(validateTarget(target).ok, true, "must parse as an IP literal");
    assert.equal(isPrivateOrLocal(target), true);
  });
}

console.log("\n[T3] IPv6 local, mapped, transition, and documentation space fails closed");
for (const target of [
  "::",
  "::1",
  "::ffff:127.0.0.1",
  "64:ff9b::127.0.0.1",
  "100::1",
  "2001::1",
  "2001:db8::1",
  "2002::1",
  "3fff::1",
  "fc00::1",
  "fd00::1",
  "fe80::1",
  "ff02::1",
]) {
  check(`${target} is rejected as non-public`, () => {
    assert.equal(validateTarget(target).ok, true, "must parse as an IP literal");
    assert.equal(isPrivateOrLocal(target), true);
  });
}

console.log("\n[T4] hostname and parser-confusion inputs never reach fetch");
for (const target of [
  "example.com",
  "localhost.localdomain",
  "2130706433",
  "127.1",
  "0177.0.0.1",
  "0x7f.0.0.1",
]) {
  check(`${target} is not accepted as an override`, () => {
    assert.equal(validateTarget(target).ok, false);
    assert.equal(isPrivateOrLocal(target), true);
  });
}

for (const target of ["::::", "1::2::3", "fe80::1%eth0", "256.1.1.1"] ) {
  check(`${target} is rejected as invalid`, () => {
    assert.equal(validateTarget(target).ok, false);
  });
}

if (failures) {
  console.error(`\n${failures} target-boundary assertion(s) failed`);
  process.exit(1);
}
console.log("\ntarget-boundary tests passed");
