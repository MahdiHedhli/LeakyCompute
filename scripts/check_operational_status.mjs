import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const wrangler = read("wrangler.toml");
const removal = read(".github/ISSUE_TEMPLATE/request_removal.yml");
const access = read(".github/ISSUE_TEMPLATE/request_research_access.yml");

const enabled = (name) => new RegExp(`^${name} = "true"$`, "m").test(wrangler);

if (enabled("ACTIVE_DISCOVERY_ENABLED")) {
  assert.doesNotMatch(removal, /active probing (?:is currently|and hosted checks are) suspended/i);
  assert.match(removal, /weekend-only\s+schedule/i);
  assert.match(removal, /immediately before a one-time permit/i);
}

if (enabled("HOSTED_CHECKS_ENABLED")) {
  assert.doesNotMatch(access, /hosted\s+self-check is currently suspended/i);
  assert.doesNotMatch(removal, /hosted checks are suspended/i);
  assert.match(access, /Turnstile-protected hosted self-check/i);
}

console.log("operational status claims match production traffic switches");
