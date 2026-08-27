import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const tracked = execFileSync("git", ["ls-files", "-z"], {
  cwd: root,
  encoding: "utf8",
}).split("\0").filter(Boolean);

const failures = [];
const fail = (message) => failures.push(message);
const privatePathPatterns = [
  new RegExp("/" + "Users/[A-Za-z0-9._-]+/"),
  new RegExp("/" + "home/[A-Za-z0-9._-]+/"),
  new RegExp("[A-Za-z]:\\\\" + "Users\\\\[A-Za-z0-9._-]+\\\\"),
  new RegExp("ThreatResearch/" + "stolencompute", "i"),
];
const privateIdentityPatterns = [
  new RegExp("@" + "42-corp\\.com", "i"),
  new RegExp("^[ \\t]*ACCESS_" + "AUD[ \\t]*=", "m"),
  new RegExp("^[ \\t]*ACCESS_TEAM_" + "DOMAIN[ \\t]*=", "m"),
  new RegExp("^[ \\t]*(?:CANARY|OWNED_CANARY)_TARGET_(?:IP|HOST)[ \\t]*=", "m"),
];

for (const path of tracked) {
  let source;
  try {
    source = read(path);
  } catch {
    continue;
  }
  if (path !== "scripts/check_public_artifacts.mjs") {
    for (const pattern of [...privatePathPatterns, ...privateIdentityPatterns]) {
      if (pattern.test(source)) fail(`${path}: contains a private path or infrastructure identity`);
    }
  }
}

const ipv4 = /(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])/;
const email = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const seedPaths = ["data/seed-models.json", "lab/data/seed-models.json"];
const seeds = seedPaths.map((path) => JSON.parse(read(path)));
assert.deepEqual(seeds[0], seeds[1], "public and lab seed catalogs must be identical");
for (const [index, entry] of seeds[0].models.entries()) {
  const name = String(entry.model || "");
  if (ipv4.test(name) || email.test(name) || privatePathPatterns.some((pattern) => pattern.test(name))) {
    fail(`seed model ${index}: contains an identifying literal`);
  }
}

assert.equal(failures.length, 0, failures.join("\n"));
console.log(`public-artifact privacy checks passed (${tracked.length} tracked files; ${seeds[0].models.length} minimized model labels)`);
