import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

const workflowDir = new URL(".github/workflows/", root);
const workflowFiles = readdirSync(workflowDir)
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => `.github/workflows/${name}`);

const discoveryWorkflow = read(".github/workflows/scheduled-discovery.yml");

const failures = [];
const fail = (message) => failures.push(message);
const actionRefs = (source) =>
  [...source.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/gm)].map(
    (match) => match[1]
  );
const isPinnedAction = (ref) =>
  ref.startsWith("./") ||
  /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/.test(ref);
const isExactVersion = (version) =>
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version);
const isDigestPinnedImage = (ref) => /@sha256:[0-9a-f]{64}$/.test(ref);

// Positive controls: a broken inventory check is worse than none.
assert.deepEqual(actionRefs("  - uses: actions/checkout@v7\n"), [
  "actions/checkout@v7",
]);
assert.equal(isPinnedAction("actions/checkout@v7"), false);
assert.equal(
  isPinnedAction(`actions/checkout@${"a".repeat(40)}`),
  true
);
assert.equal(isExactVersion("^4.0.0"), false);
assert.equal(isExactVersion("4.126.0"), true);
assert.equal(isDigestPinnedImage("python:3.11-slim"), false);
assert.equal(
  isDigestPinnedImage(`python:3.11-slim@sha256:${"a".repeat(64)}`),
  true
);

for (const file of workflowFiles) {
  const source = read(file);

  if (/\bruns-on:\s*\S+-latest\b/.test(source)) {
    fail(`${file}: runner image must not use a mutable *-latest label`);
  }

  for (const ref of actionRefs(source)) {
    if (!isPinnedAction(ref)) {
      fail(`${file}: action is not pinned to a full commit SHA: ${ref}`);
    }
  }

  for (const match of source.matchAll(/\bwrangler@([^\s"']+)/g)) {
    if (!isExactVersion(match[1])) {
      fail(`${file}: Wrangler must use an exact version, found ${match[0]}`);
    }
  }

  for (const match of source.matchAll(
    /^\s*(?:node|python)-version:\s*["']?([^\s"']+)/gm
  )) {
    if (!isExactVersion(match[1])) {
      fail(`${file}: tool runtime must use an exact patch version: ${match[1]}`);
    }
  }
}

if (!/cron:\s*["']43 5 \* \* 0,6["']/.test(discoveryWorkflow)) {
  fail("scheduled discovery must remain weekend-only and off the hour");
}
const uploadedArtifacts = [...discoveryWorkflow.matchAll(/uses:\s*actions\/upload-artifact@/g)];
if (
  uploadedArtifacts.length !== 1 ||
  !/name:\s*opaque-discovery-nominations/.test(discoveryWorkflow) ||
  !/path:\s*nomination-manifest\.json/.test(discoveryWorkflow) ||
  !/retention-days:\s*1/.test(discoveryWorkflow) ||
  /path:\s*discovery-run\.json/.test(discoveryWorkflow)
) {
  fail("scheduled discovery may upload only the one-day opaque nomination manifest");
}
if (
  !/jobs:\s*[\s\S]*preflight:[\s\S]*nominate:[\s\S]*probe:/.test(discoveryWorkflow) ||
  !/nominate:[\s\S]*LEAKY_NOMINATOR_TOKEN:[\s\S]*probe:[\s\S]*LEAKY_ADMIN_TOKEN:/.test(discoveryWorkflow)
) {
  fail("scheduled discovery must split nomination and probe credentials across jobs");
}
if (!/Verify strong control plane/.test(discoveryWorkflow) ||
    !/\/v1\/admin\/control\/health/.test(discoveryWorkflow) ||
    !/\.ready == true/.test(discoveryWorkflow)) {
  fail("scheduled discovery must fail before index access unless strong storage is ready");
}
if (!/Publish current aggregate generation/.test(discoveryWorkflow) ||
    !/\/v1\/admin\/control\/reconcile/.test(discoveryWorkflow)) {
  fail("scheduled discovery must publish authoritative aggregates before downstream hooks run");
}
if (!/max_total[^\n]*\n\s+description:[^\n]*\n\s+default:\s*["']120["']/.test(discoveryWorkflow)) {
  fail("scheduled discovery must retain the reviewed 120-candidate default");
}

const packageJson = JSON.parse(read("package.json"));
for (const section of ["dependencies", "devDependencies"]) {
  for (const [name, version] of Object.entries(packageJson[section] || {})) {
    if (!isExactVersion(version)) {
      fail(`package.json: ${section}.${name} is not exact: ${version}`);
    }
  }
}

const lock = JSON.parse(read("package-lock.json"));
assert.equal(lock.lockfileVersion, 3, "package-lock.json must use lockfileVersion 3");
assert.equal(
  lock.packages?.[""]?.devDependencies?.wrangler,
  packageJson.devDependencies.wrangler,
  "package-lock root Wrangler version must match package.json"
);
assert.match(
  lock.packages?.["node_modules/wrangler"]?.integrity || "",
  /^sha512-/,
  "locked Wrangler package must carry an integrity hash"
);
for (const name of Object.keys(packageJson.devDependencies || {})) {
  assert.match(
    lock.packages?.[`node_modules/${name}`]?.integrity || "",
    /^sha512-/,
    `locked ${name} package must carry an integrity hash`
  );
}

const composeFile = "scripts/discovery/local-lab/docker-compose.yml";
const compose = read(composeFile);
for (const match of compose.matchAll(/^\s*image:\s*["']?([^\s"']+)/gm)) {
  if (!isDigestPinnedImage(match[1])) {
    fail(`${composeFile}: image is not pinned to a digest: ${match[1]}`);
  }
}
if (!/\bpip install\b[\s\S]*?--require-hashes/.test(compose)) {
  fail(`${composeFile}: TensorBoard fixture must require package hashes`);
}

const tensorboardLockFile =
  "scripts/discovery/local-lab/tensorboard-requirements.lock";
const tensorboardLock = read(tensorboardLockFile)
  .replace(/\\\n\s*/g, " ")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"));
for (const requirement of tensorboardLock) {
  if (!/^[a-z0-9-]+==\d+(?:\.\d+)+\s+/i.test(requirement)) {
    fail(`${tensorboardLockFile}: dependency is not exact: ${requirement}`);
  }
  if (!/--hash=sha256:[0-9a-f]{64}/.test(requirement)) {
    fail(`${tensorboardLockFile}: dependency has no SHA-256 hash: ${requirement}`);
  }
}

assert.equal(failures.length, 0, failures.join("\n"));
console.log(
  `supply-chain checks passed (${workflowFiles.length} workflows; ` +
    `${Object.keys(packageJson.devDependencies || {}).length} locked dev dependency; ` +
    `${[...compose.matchAll(/^\s*image:/gm)].length} digest-pinned images; ` +
    `${tensorboardLock.length} hash-locked Python packages)`
);
