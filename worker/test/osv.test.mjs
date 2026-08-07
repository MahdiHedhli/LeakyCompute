/**
 * Tier-2 OSV unit tests — mock fetch + in-memory KV, no live OSV required
 * for the happy path (optional live smoke is skipped if OFFLINE).
 */
import assert from "node:assert/strict";
import {
  OSV_PACKAGES,
  queryOsv,
  enrichServicesWithOsv,
} from "../src/lib/osv.js";

function makeKV() {
  const store = new Map();
  return {
    _store: store,
    async get(k, type) {
      const v = store.get(k);
      if (v === undefined) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(k, v) {
      store.set(k, v);
    },
  };
}

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

console.log("\n[osv] package map + query/enrich");

await check("OSV_PACKAGES covers tier-1 stacks", () => {
  assert.equal(OSV_PACKAGES.ollama.ecosystem, "Go");
  assert.equal(OSV_PACKAGES.ollama.name, "github.com/ollama/ollama");
  assert.equal(OSV_PACKAGES.ray.ecosystem, "PyPI");
  assert.equal(OSV_PACKAGES.jupyter.name, "jupyter_server");
});

await check("queryOsv returns [] without version", async () => {
  const out = await queryOsv(OSV_PACKAGES.ollama, "", { KV: makeKV() });
  assert.deepEqual(out, []);
});

await check("queryOsv returns [] without package", async () => {
  const out = await queryOsv(null, "0.6.2", { KV: makeKV() });
  assert.deepEqual(out, []);
});

// Mock global fetch for OSV
const originalFetch = globalThis.fetch;
const mockVulns = {
  vulns: [
    {
      id: "GHSA-test-0001",
      aliases: ["CVE-2024-99999"],
      summary: "Test Ollama vulnerability for unit tests",
      published: "2024-01-01T00:00:00Z",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      references: [{ url: "https://example.com/advisory" }],
    },
  ],
};

globalThis.fetch = async (url, opts) => {
  if (String(url).includes("osv.dev")) {
    const body = JSON.parse(opts.body);
    assert.equal(body.package.name, "github.com/ollama/ollama");
    assert.equal(body.version, "0.1.46");
    return {
      ok: true,
      async json() {
        return mockVulns;
      },
    };
  }
  return originalFetch(url, opts);
};

const kv = makeKV();

await check("queryOsv normalizes vulns + caches", async () => {
  const vulns = await queryOsv(OSV_PACKAGES.ollama, "v0.1.46", { KV: kv });
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0].id, "GHSA-test-0001");
  assert.equal(vulns[0].cve, "CVE-2024-99999");
  assert.equal(vulns[0].severity, "critical");
  assert.equal(vulns[0].source, "osv.dev");
  // second call hits cache — replace fetch to fail if called
  globalThis.fetch = async () => {
    throw new Error("should use KV cache");
  };
  const cached = await queryOsv(OSV_PACKAGES.ollama, "0.1.46", { KV: kv });
  assert.equal(cached.length, 1);
  assert.equal(cached[0].id, "GHSA-test-0001");
});

// restore mock for enrich
globalThis.fetch = async (url, opts) => {
  if (String(url).includes("osv.dev")) {
    return {
      ok: true,
      async json() {
        return mockVulns;
      },
    };
  }
  return originalFetch(url, opts);
};

await check("enrichServicesWithOsv attaches osv[] + findings", async () => {
  const services = [
    {
      service: "ollama",
      detected: true,
      exposed: true,
      version: "0.1.46",
      findings: [{ id: "exposure", title: "open", severity: "high" }],
    },
    {
      service: "unknown_stack",
      detected: true,
      exposed: true,
      version: "1.0.0",
      findings: [],
    },
  ];
  await enrichServicesWithOsv(services, { KV: makeKV() });
  assert.equal(services[0].osv.length, 1);
  assert.ok(services[0].findings.some((f) => f.source === "osv.dev"));
  assert.deepEqual(services[1].osv, []);
});

await check("enrich skips when not detected / no version", async () => {
  const services = [
    { service: "ollama", detected: false, version: "0.1.46", findings: [] },
    { service: "ollama", detected: true, version: null, findings: [] },
  ];
  await enrichServicesWithOsv(services, { KV: makeKV() });
  assert.deepEqual(services[0].osv, []);
  assert.deepEqual(services[1].osv, []);
});

globalThis.fetch = originalFetch;

if (failures) {
  console.error(`\n${failures} osv test(s) failed`);
  process.exit(1);
}
console.log("\nosv tests passed");
