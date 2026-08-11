/**
 * Researcher lab — corpus browser, cross-tab map, and per-host validation over
 * /v1/research/lab/*.
 *
 * Three rules this file is written to keep visible rather than assumed:
 *
 *  - I-16. Nothing reaches the DOM except through util.js's `h`, which escapes
 *    every substitution. Probed-host strings (versions, orgs, model names) are
 *    rendered as text, never as markup, never as a URL.
 *  - I-20. The only host this page ever talks to is our own Worker (api.js).
 *    Selecting a host loads a stored record; it does not contact the host.
 *  - I-14 / I-27. Addresses stay out of the URL, out of history, and out of the
 *    referer: filter state is mirrored into the location hash, the selected
 *    address deliberately is not. A display-only mask exists for screen shares,
 *    because lab access is not publication clearance.
 */

import * as api from "./api.js";
import { h, html, render, chip, esc, stamp, fmt } from "./util.js";
import { corpusView, mapView, validationView, hostView, errorBox } from "./views.js";

const $ = (id) => document.getElementById(id);

/* Tier-1 services (docs/SECURITY.md I-2). Facets from the corpus are merged in. */
const KNOWN_STACKS = ["ollama", "ray", "jupyter"];
const STATES = ["answering", "stale", "silent", "expired", "unverified"];

const LIST_FIELDS = ["stack", "country", "asn", "source", "state"];
const TEXT_FIELDS = [
  "q",
  "org",
  "cidr",
  "version",
  "version_prefix",
  "has_version",
  "vuln",
  "first_seen_after",
  "first_seen_before",
  "last_seen_after",
  "last_seen_before",
];

const state = {
  view: "corpus",
  page: 1,
  page_size: 50,
  limit: 500,
  sort: "last_seen",
  order: "desc",
  bucket: "week",
  osv: false,
  masked: localStorage.getItem("lab.mask") === "1",
  filters: emptyFilters(),
};

let facets = { stack: [], country: [], asn: [], org: [], source: [], version: [] };
let selectedIp = null;
let busy = false;
let lastPage = null;

function emptyFilters() {
  const f = {};
  for (const k of LIST_FIELDS) f[k] = [];
  for (const k of TEXT_FIELDS) f[k] = "";
  return f;
}

/* ------------------------------------------------------------------ */
/* Query state <-> location hash                                       */
/* ------------------------------------------------------------------ */

function toParams() {
  const p = {
    limit: state.limit,
    page: state.page,
    page_size: state.page_size,
    sort: state.sort,
    order: state.order,
  };
  for (const k of LIST_FIELDS) if (state.filters[k].length) p[k] = state.filters[k];
  for (const k of TEXT_FIELDS) if (state.filters[k]) p[k] = state.filters[k];
  return p;
}

function writeHash() {
  const p = new URLSearchParams();
  p.set("view", state.view);
  for (const k of LIST_FIELDS) if (state.filters[k].length) p.set(k, state.filters[k].join(","));
  for (const k of TEXT_FIELDS) if (state.filters[k]) p.set(k, state.filters[k]);
  for (const k of ["sort", "order", "page", "page_size", "limit"]) p.set(k, String(state[k]));
  if (state.osv) p.set("osv", "1");
  // The selected address is intentionally absent: an address in the URL bar is
  // an address in browser history, in a screenshot, and in any referer that
  // leaks from this page (I-14).
  history.replaceState(null, "", `#${p.toString()}`);
}

function readHash() {
  const p = new URLSearchParams(location.hash.replace(/^#/, ""));
  if (!p.toString()) return;
  const view = p.get("view");
  if (["corpus", "map", "validation"].includes(view)) state.view = view;
  for (const k of LIST_FIELDS) {
    const v = p.get(k);
    state.filters[k] = v ? v.split(",").map((s) => s.trim()).filter(Boolean) : [];
  }
  for (const k of TEXT_FIELDS) state.filters[k] = p.get(k) || "";
  for (const k of ["page", "page_size", "limit"]) {
    const n = parseInt(p.get(k) || "", 10);
    if (Number.isInteger(n) && n > 0) state[k] = n;
  }
  if (p.get("sort")) state.sort = p.get("sort");
  if (p.get("order") === "asc" || p.get("order") === "desc") state.order = p.get("order");
  state.osv = p.get("osv") === "1";
}

/* ------------------------------------------------------------------ */
/* Filter form                                                         */
/* ------------------------------------------------------------------ */

function choiceRow(field, values, selected) {
  if (!values.length) return h`<span class="dim">—</span>`;
  return h`${values.map(
    (v) =>
      h`<button type="button" class="choice ${selected.includes(v) ? "on" : ""}" data-field="${field}" data-value="${v}">${v}</button>`
  )}`;
}

function paintChoices() {
  const stacks = [...new Set([...KNOWN_STACKS, ...facets.stack])];
  render($("f-stack"), choiceRow("stack", stacks, state.filters.stack));
  render($("f-state"), choiceRow("state", STATES, state.filters.state));
}

function paintDatalists() {
  const fill = (id, values) =>
    render($(id), h`${values.slice(0, 200).map((v) => h`<option value="${v}"></option>`)}`);
  fill("dl-country", facets.country);
  fill("dl-asn", facets.asn);
  fill("dl-org", facets.org);
  fill("dl-source", facets.source);
  fill("dl-version", facets.version);
}

function paintForm() {
  for (const k of TEXT_FIELDS) {
    const el = $(`f-${k.replace(/_/g, "-")}`);
    if (el) el.value = state.filters[k];
  }
  $("f-sort").value = state.sort;
  $("f-order").value = state.order;
  $("f-page-size").value = String(state.page_size);
  $("f-limit").value = String(state.limit);
  $("osv-btn").classList.toggle("on", state.osv);
  $("mask-btn").classList.toggle("on", state.masked);
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.view === state.view));
  paintChoices();
}

function readForm() {
  for (const k of TEXT_FIELDS) {
    const el = $(`f-${k.replace(/_/g, "-")}`);
    if (el) state.filters[k] = el.value.trim();
  }
  state.sort = $("f-sort").value;
  state.order = $("f-order").value;
  state.page_size = parseInt($("f-page-size").value, 10) || 50;
  state.limit = parseInt($("f-limit").value, 10) || 500;
}

function activeFilterCount() {
  let n = 0;
  for (const k of LIST_FIELDS) if (state.filters[k].length) n++;
  for (const k of TEXT_FIELDS) if (state.filters[k]) n++;
  return n;
}

/* ------------------------------------------------------------------ */
/* Loading                                                             */
/* ------------------------------------------------------------------ */

function setStatus(node) {
  render($("status"), node);
}

async function load() {
  if (busy) return;
  busy = true;
  writeHash();
  paintForm();
  setStatus(h`<span class="pulse">querying corpus…</span>`);
  const params = toParams();
  const started = performance.now();

  let result;
  if (state.view === "map") result = await api.map({ ...params, bucket: state.bucket });
  else if (state.view === "validation") result = await api.validation({ ...params, osv: state.osv ? "1" : null });
  else result = await api.catalog(params);

  busy = false;
  const ms = Math.round(performance.now() - started);
  const { ok, status, data } = result;

  if (!ok) {
    setStatus(h`<span class="bad">query refused · HTTP ${Number(status)}</span>`);
    render($("content"), errorBox(status, data));
    return;
  }

  if (state.view === "map") absorbFacets(data);
  lastPage = data.page || null;

  const opts = { masked: state.masked };
  const node =
    state.view === "map" ? mapView(data) : state.view === "validation" ? validationView(data, opts) : corpusView(data, opts);
  render($("content"), node);
  $("content").scrollTop = 0;
  bindContent();

  const shown =
    state.view === "map"
      ? `${fmt(data.totals?.hosts)} hosts aggregated`
      : `${fmt(data.page?.total)} matching · page ${fmt(data.page?.page)}/${fmt(data.page?.pages)}`;
  setStatus(
    h`${shown} · ${fmt(activeFilterCount())} filters · generated ${stamp(data.generated_at)} · ${Number(ms)}ms
      ${state.masked ? chip("addresses masked", "warn") : ""}`
  );
}

/** Facets come from the corpus, so they are probed-derived strings — escaped like everything else. */
function absorbFacets(data) {
  const keys = (block) => (block?.top || []).map((r) => r.key).filter((k) => typeof k === "string");
  facets = {
    stack: keys(data.by_stack),
    country: keys(data.by_country),
    asn: keys(data.by_asn),
    org: keys(data.by_org),
    source: keys(data.by_source),
    version: keys(data.by_version),
  };
  paintDatalists();
  paintChoices();
}

/* ------------------------------------------------------------------ */
/* Host detail panel                                                   */
/* ------------------------------------------------------------------ */

async function openHost(ip, includeModels) {
  selectedIp = ip;
  $("host-panel").hidden = false;
  render($("host-title"), h`${state.masked ? "host detail" : ip}`);
  render($("host-body"), h`<p class="pulse">reading stored record…</p>`);
  const { ok, status, data } = await api.host(ip, { includeModels });
  if (!ok) {
    render($("host-body"), errorBox(status, data));
    return;
  }
  render($("host-body"), hostView(data, { masked: state.masked }));
  const btn = $("load-models");
  if (btn) btn.onclick = () => openHost(ip, true);
}

function closeHost() {
  $("host-panel").hidden = true;
  selectedIp = null;
}

/* ------------------------------------------------------------------ */
/* Event wiring                                                        */
/* ------------------------------------------------------------------ */

function bindContent() {
  const content = $("content");
  content.querySelectorAll("[data-ip]").forEach((el) => {
    const open = () => openHost(el.dataset.ip, false);
    el.addEventListener("click", open);
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open();
      }
    });
  });
  content.querySelectorAll("[data-page]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pages = Number(lastPage?.pages) || 1;
      const move = btn.dataset.page;
      if (move === "first") state.page = 1;
      else if (move === "prev") state.page = Math.max(1, state.page - 1);
      else if (move === "next") state.page = Math.min(pages, state.page + 1);
      else if (move === "last") state.page = Math.max(1, pages);
      load();
    });
  });
}

function bindChrome() {
  $("filters").addEventListener("submit", (e) => {
    e.preventDefault();
    readForm();
    state.page = 1;
    load();
  });

  $("filters").addEventListener("click", (e) => {
    const btn = e.target.closest(".choice");
    if (!btn) return;
    const { field, value } = btn.dataset;
    const list = state.filters[field];
    const i = list.indexOf(value);
    if (i >= 0) list.splice(i, 1);
    else list.push(value);
    state.page = 1;
    paintChoices();
    load();
  });

  $("reset-btn").addEventListener("click", () => {
    state.filters = emptyFilters();
    state.page = 1;
    paintForm();
    load();
  });

  document.querySelectorAll("#tabs button").forEach((b) => {
    b.addEventListener("click", () => {
      state.view = b.dataset.view;
      state.page = 1;
      load();
    });
  });

  $("refresh-btn").addEventListener("click", () => load());

  $("osv-btn").addEventListener("click", () => {
    state.osv = !state.osv;
    if (state.view !== "validation") state.view = "validation";
    load();
  });

  $("mask-btn").addEventListener("click", () => {
    state.masked = !state.masked;
    localStorage.setItem("lab.mask", state.masked ? "1" : "0");
    paintForm();
    if (selectedIp) openHost(selectedIp, false);
    load();
  });

  $("host-close").addEventListener("click", closeHost);
  $("host-copy").addEventListener("click", async () => {
    if (!selectedIp) return;
    try {
      await navigator.clipboard.writeText(selectedIp);
      $("host-copy").textContent = "COPIED";
      setTimeout(() => ($("host-copy").textContent = "COPY ADDR"), 1200);
    } catch {
      $("host-copy").textContent = "DENIED";
      setTimeout(() => ($("host-copy").textContent = "COPY ADDR"), 1200);
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeHost();
  });

  $("collapse-btn").addEventListener("click", () => $("app").classList.add("sb-hidden"));
  $("expand-btn").addEventListener("click", () => $("app").classList.remove("sb-hidden"));
  $("sb-backdrop").addEventListener("click", () => $("app").classList.add("sb-hidden"));
}

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

function identityBox(status, data) {
  if (data?.allowed) {
    return h`<div class="ident good"><strong>@${data.login || "?"}</strong> · researcher access · read-only corpus</div>`;
  }
  if (data?.authenticated) {
    return h`<div class="ident bad"><strong>@${data.login || "?"}</strong> not allowlisted ·
      <a href="${(window.LEAKY_LAB_CONFIG || {}).ACCESS_ISSUE_URL || "#"}" target="_blank" rel="noopener noreferrer">request access</a></div>`;
  }
  if (status === 0) {
    return h`<div class="ident bad">lab API unreachable · set API_BASE in lab/js/config.js</div>`;
  }
  return h`<div class="ident"><strong>lab gate</strong> · sign in with GitHub via Cloudflare Access, or run wrangler and append
    <code>?dev_user=you</code> ·
    <a href="${(window.LEAKY_LAB_CONFIG || {}).ACCESS_ISSUE_URL || "#"}" target="_blank" rel="noopener noreferrer">request access</a></div>`;
}

(async function boot() {
  readHash();
  bindChrome();
  paintForm();

  const me = await api.whoami();
  render($("identity"), identityBox(me.status, me.data));

  if (!me.data?.allowed) {
    // No corpus request is attempted without access: the gate is server-side
    // (lab.js), and there is nothing useful to render from a refusal but the
    // refusal itself.
    setStatus(h`<span class="bad">locked</span>`);
    const status = me.status >= 400 ? me.status : me.status === 0 ? 0 : me.data?.authenticated ? 403 : 401;
    const payload = me.data?.error
      ? me.data
      : { error: status === 0 ? "unreachable" : status === 403 ? "forbidden" : "unauthorized" };
    render($("content"), errorBox(status, payload));
    return;
  }

  await load();
  // The map call doubles as the facet source for the filter datalists.
  if (state.view !== "map") {
    const m = await api.map({ limit: state.limit });
    if (m.ok) absorbFacets(m.data);
  }
})();

// Exported for console poking during development; nothing here mutates a target.
window.LAB = { state, load, openHost, esc, html };
