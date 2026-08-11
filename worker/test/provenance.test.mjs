/**
 * I-22 and I-24 are enforced in the off-Worker runner, which is Python. The
 * assertions live in governance_gates.py; this wrapper exists so `npm test`
 * remains the single command that says whether the invariants hold.
 *
 * A missing interpreter is reported as a failure, not skipped: "the provenance
 * gate is untested on this machine" and "the provenance gate passed" must not
 * look the same in CI output.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SUITE = path.join(HERE, "governance_gates.py");

const probe = spawnSync("python3", ["--version"], { encoding: "utf8" });
if (probe.error || probe.status !== 0) {
  console.error(
    "\n[provenance] python3 is required: I-22 (provenance) and I-24 (re-probe " +
      "interval, rate ceilings) are enforced in scripts/discovery and cannot be " +
      "checked without it.\n"
  );
  process.exit(1);
}

const run = spawnSync("python3", [SUITE], { stdio: "inherit" });
process.exit(run.status == null ? 1 : run.status);
