#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import sharp from "sharp";

const ROOT = path.resolve(import.meta.dirname, "..");
const BASE_IMAGE = path.join(ROOT, "public/assets/leakycompute-social-base.png");
const OUTPUT_IMAGE = path.join(ROOT, "public/assets/leakycompute-social-preview.png");
const INDEX_HTML = path.join(ROOT, "public/index.html");
const API_BASE = (process.env.LEAKY_API_BASE || "https://api.leakycompute.mahdihedhli.com").replace(/\/+$/, "");
const SOCIAL_IMAGE_URL = "https://leakycompute.mahdihedhli.com/assets/leakycompute-social-preview.png";

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : process.argv[index + 1];
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100_000_000) {
    throw new Error(`${label} must be a bounded non-negative integer`);
  }
  return value;
}

function escapeXml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&apos;",
  })[character]);
}

function validateStats(stats, allowDegraded) {
  if (!stats || typeof stats !== "object" || Array.isArray(stats)) {
    throw new Error("stats response must be an object");
  }
  if (stats.control_plane_degraded === true && !allowDegraded) {
    throw new Error("strong control plane is degraded; preserving the last good social card");
  }

  const updatedAt = new Date(stats.updated_at);
  if (!Number.isFinite(updatedAt.getTime())) {
    throw new Error("stats.updated_at is not a valid timestamp");
  }
  if (updatedAt.getTime() > Date.now() + 5 * 60 * 1000) {
    throw new Error("stats.updated_at is unexpectedly in the future");
  }

  return {
    archive: integer(stats.archive_snapshot?.hosts, "archive_snapshot.hosts"),
    indexed: integer(
      stats.indexed_observed?.records ?? stats.indexed_observed?.hosts,
      "indexed_observed.records"
    ),
    reverified: integer(stats.reverified?.hosts, "reverified.hosts"),
    updatedAt,
  };
}

async function loadStats() {
  const statsFile = argValue("--stats-file");
  if (statsFile) {
    return JSON.parse(await readFile(path.resolve(statsFile), "utf8"));
  }

  const response = await fetch(`${API_BASE}/v1/stats`, {
    headers: { accept: "application/json" },
    cache: "no-store",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    throw new Error(`stats request failed with HTTP ${response.status}`);
  }
  return response.json();
}

function card({ x, color, label, number, sublabel }) {
  return `
    <g>
      <rect x="${x}" y="126" width="344" height="244" rx="20"
        fill="#07101ce8" stroke="${color}" stroke-width="2"/>
      <text x="${x + 172}" y="177" text-anchor="middle" fill="${color}"
        font-family="Arial, Helvetica, sans-serif" font-size="19" font-weight="700"
        letter-spacing="3">${escapeXml(label)}</text>
      <text x="${x + 172}" y="285" text-anchor="middle" fill="${color}"
        font-family="Arial, Helvetica, sans-serif" font-size="78" font-weight="800"
        letter-spacing="-2">${escapeXml(number)}</text>
      <text x="${x + 172}" y="337" text-anchor="middle" fill="#e8eef7"
        font-family="Arial, Helvetica, sans-serif" font-size="18" font-weight="600"
        letter-spacing="3">${escapeXml(sublabel)}</text>
    </g>`;
}

function overlay({ archive, indexed, reverified, updatedAt }) {
  const format = new Intl.NumberFormat("en-US");
  const asOf = new Intl.DateTimeFormat("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(updatedAt).toUpperCase();

  return Buffer.from(`
  <svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
    <rect width="1200" height="630" fill="#02091466"/>
    <rect x="0" y="0" width="1200" height="104" fill="#020812e8"/>
    <text x="52" y="54" fill="#f5f7fb" font-family="Arial, Helvetica, sans-serif"
      font-size="34" font-weight="800" letter-spacing="5">LEAKY COMPUTE</text>
    <text x="52" y="82" fill="#9eacc0" font-family="Arial, Helvetica, sans-serif"
      font-size="14" font-weight="700" letter-spacing="3">DEFENSIVE EXPOSURE RESEARCH // FIELD PULSE</text>
    <text x="1148" y="62" text-anchor="end" fill="#aab7c9"
      font-family="Arial, Helvetica, sans-serif" font-size="16" font-weight="700"
      letter-spacing="2">THREE MEASUREMENTS • NEVER SUMMED</text>

    ${card({ x: 50, color: "#ffb01f", label: "ARCHIVE SNAPSHOT", number: format.format(archive), sublabel: "HOSTS LISTED" })}
    ${card({ x: 428, color: "#ff5b4d", label: "PUBLIC-INDEX MATCHES", number: format.format(indexed), sublabel: "RECORDS OBSERVED" })}
    ${card({ x: 806, color: "#18c8ff", label: "ROLLING RE-VERIFIED", number: format.format(reverified), sublabel: "HOSTS RETAINED" })}

    <rect x="0" y="558" width="1200" height="72" fill="#020812e8"/>
    <text x="600" y="593" text-anchor="middle" fill="#eef3fa"
      font-family="Arial, Helvetica, sans-serif" font-size="17" font-weight="700"
      letter-spacing="4">AS OF ${escapeXml(asOf)} • LEAKYCOMPUTE.MAHDIHEDHLI.COM</text>
  </svg>`);
}

function versionFor(updatedAt) {
  return updatedAt.toISOString().replace(/\D/g, "").slice(0, 14);
}

async function updateMeta(version) {
  const html = await readFile(INDEX_HTML, "utf8");
  const nextUrl = `${SOCIAL_IMAGE_URL}?v=${version}`;
  const pattern = new RegExp(`${SOCIAL_IMAGE_URL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\?v=[0-9]{14}`, "g");
  const matches = html.match(pattern) || [];
  if (matches.length < 2) {
    throw new Error("index.html must contain both Open Graph and Twitter social-card URLs");
  }
  await writeFile(INDEX_HTML, html.replace(pattern, nextUrl));
}

const stats = validateStats(
  await loadStats(),
  process.argv.includes("--allow-degraded")
);

await sharp(BASE_IMAGE)
  .resize(1200, 630, { fit: "cover", position: "centre" })
  .composite([{ input: overlay(stats), top: 0, left: 0 }])
  .png({ compressionLevel: 9, adaptiveFiltering: true })
  .toFile(OUTPUT_IMAGE);

await updateMeta(versionFor(stats.updatedAt));
console.log(
  `social preview updated: archive=${stats.archive}, indexed=${stats.indexed}, ` +
  `reverified=${stats.reverified}, as_of=${stats.updatedAt.toISOString()}`
);
