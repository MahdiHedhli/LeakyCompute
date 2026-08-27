import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const root = new URL("../", import.meta.url);
const index = await readFile(new URL("public/index.html", root), "utf8");
const workflow = await readFile(
  new URL(".github/workflows/update-social-preview.yml", root),
  "utf8"
);
const renderer = await readFile(
  new URL("scripts/update_social_preview.mjs", root),
  "utf8"
);

for (const required of [
  'property="og:type" content="website"',
  'property="og:image:type" content="image/png"',
  'property="og:image:width" content="1200"',
  'property="og:image:height" content="630"',
  'name="twitter:card" content="summary_large_image"',
  'rel="canonical" href="https://leakycompute.mahdihedhli.com/index.html"',
]) {
  assert.match(index, new RegExp(required), `missing social metadata: ${required}`);
}

const imageUrls = [
  ...index.matchAll(
    /https:\/\/leakycompute\.mahdihedhli\.com\/assets\/leakycompute-social-preview\.png\?v=([0-9]{14})/g
  ),
];
assert.ok(imageUrls.length >= 3, "Open Graph, secure image, and Twitter must share the versioned card");
assert.equal(
  new Set(imageUrls.map((match) => match[0])).size,
  1,
  "every social metadata surface must use the same cache-busted card"
);

const metadata = await sharp(
  fileURLToPath(new URL("public/assets/leakycompute-social-preview.png", root))
).metadata();
assert.equal(metadata.format, "png");
assert.equal(metadata.width, 1200);
assert.equal(metadata.height, 630);

assert.match(workflow, /workflow_run:[\s\S]*workflows: \["Governed discovery"\]/);
assert.match(workflow, /github\.event\.workflow_run\.conclusion == 'success'/);
assert.match(workflow, /permissions:\s*\n\s*contents: write/);
assert.doesNotMatch(workflow, /\$\{\{\s*secrets\./, "preview refresh must use no repository secrets");
assert.match(workflow, /run: npm ci/);
assert.match(renderer, /control_plane_degraded === true/);
assert.match(renderer, /preserving the last good social card/);

console.log("social preview checks passed (metadata, 1200x630 PNG, fail-closed refresh)");
