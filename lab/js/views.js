/**
 * Lab views — pure functions from a lab API payload to markup.
 *
 * I-16: nothing in this file interpolates a value into markup except through
 * the `h` tagged template, which escapes it. Probed-host strings (version,
 * product, org, city, country, model names, OSV titles) are never passed to
 * `raw()`, never used as an href/src, and never written to a DOM property that
 * parses markup.
 *
 * I-20: no view renders a link, form, iframe, image, or button that would cause
 * a request to a discovered host. Addresses are text and a copy affordance,
 * nothing more. If a future view is tempted to add "test this endpoint", that
 * is the one thing the lab must never grow.
 */

import {
  h,
  chip,
  stateChip,
  sevChip,
  discloseChip,
  fmt,
  pct,
  width,
  heat,
  stamp,
  day,
  days,
  empty,
} from "./util.js";

/* ------------------------------------------------------------------ */
/* Shared furniture                                                    */
/* ------------------------------------------------------------------ */

/**
 * Screenshot / screen-share guard. Lab access is not publication clearance
 * (I-27), and a talk slide is a publication. Masking is presentation-only:
 * the address is still in the payload, so this is a courtesy, not a control.
 */
export function addressLabel(ip, index, masked) {
  if (!masked) return h`<span class="ip">${ip}</span>`;
  return h`<span class="ip masked" title="Address masked for display only">host-${Number(index) + 1}</span>`;
}

export function errorBox(status, data) {
  const code = data?.error || "error";
  const hints = {
    unauthorized:
      "Sign in with GitHub through Cloudflare Access. Local dev: append ?dev_user=<your-login> and run wrangler.",
    forbidden: "Your GitHub identity is recognised but not on the researcher allowlist.",
    rate_limited: "Lab query rate limit reached — the corpus is expensive to assemble. Wait for the window to reset.",
    corpus_unavailable: "No corpus store is bound to this Worker.",
    exclusions_unreadable:
      "The exclusion list could not be read, so the corpus is withheld. This fails closed by design (I-25).",
    record_excluded:
      "This address space is on the exclusion list. The record is withheld and scheduled for deletion (I-25).",
    not_found: "No record for that address in the corpus.",
    unreachable: "The lab API did not answer. Check API_BASE in lab/js/config.js.",
  };
  return h`<div class="notice bad">
    <div class="notice-head">${code.replace(/_/g, " ")} ${chip(`HTTP ${Number(status) || 0}`)}</div>
    <p>${data?.message || hints[code] || "The lab API refused this request."}</p>
    ${hints[code] && data?.message ? h`<p class="dim">${hints[code]}</p>` : ""}
    ${data?.reset ? h`<p class="dim">Resets at ${stamp(data.reset)}.</p>` : ""}
  </div>`;
}

export function corpusBanner(env) {
  const c = env?.corpus;
  if (!c) return "";
  return h`<div class="notice ${c.truncated ? "warn" : ""}">
    <div class="notice-head">
      corpus ${chip(`${fmt(c.records)} records`)}
      ${chip(`scan cap ${fmt(c.scan_cap)}`, c.truncated ? "warn" : "")}
      ${c.excluded_suppressed ? chip(`${fmt(c.excluded_suppressed)} suppressed by exclusion`, "warn") : ""}
      ${chip(`I-16: ${fmt((env.untrusted_fields || []).length)} untrusted fields escaped on render`, "live")}
    </div>
    <p>${c.note}</p>
    ${c.excluded_suppressed
      ? h`<p class="dim">Suppressed rows are hosts inside excluded space. They are withheld before rendering and are queued for deletion (I-25).</p>`
      : ""}
  </div>`;
}

export function limitationsBox(list) {
  if (!list || !list.length) return "";
  return h`<details class="limits">
    <summary>limitations — what these numbers are not</summary>
    <ul>${list.map((l) => h`<li>${l}</li>`)}</ul>
  </details>`;
}

function caveatBox(title, list) {
  if (!list || !list.length) return "";
  return h`<div class="notice">
    <div class="notice-head">${title}</div>
    <ul class="tight">${list.map((c) => h`<li>${c}</li>`)}</ul>
  </div>`;
}

function tile(value, label, hint) {
  return h`<div class="tile"${hint ? h` title="${hint}"` : ""}>
    <div class="val">${value}</div><div class="lbl">${label}</div>
  </div>`;
}

/* ------------------------------------------------------------------ */
/* Corpus browser                                                      */
/* ------------------------------------------------------------------ */

export function corpusView(data, opts) {
  const hosts = data.hosts || [];
  if (!hosts.length) {
    return h`${corpusBanner(data)}${empty("No host matches these filters.")}${limitationsBox(data.limitations)}`;
  }
  return h`
    ${corpusBanner(data)}
    <div class="table-wrap">
      <table class="grid">
        <thead>
          <tr>
            <th>address</th>
            <th>stack / ports</th>
            <th>version</th>
            <th>geo</th>
            <th>network</th>
            <th>seen</th>
            <th>state</th>
          </tr>
        </thead>
        <tbody>
          ${hosts.map((row, i) => corpusRow(row, i, opts))}
        </tbody>
      </table>
    </div>
    ${pager(data.page)}
    ${limitationsBox(data.limitations)}`;
}

function corpusRow(row, index, opts) {
  const v = row.verification || {};
  return h`<tr class="hostrow" data-ip="${row.ip}" tabindex="0">
    <td class="cell-ip">
      ${addressLabel(row.ip, index, opts.masked)}
      <div class="sub">${row.source || "source unknown"}</div>
    </td>
    <td>
      ${(row.stacks || []).map((s) => chip(s, "live"))}
      <div class="sub">${(row.ports || []).map((p) => Number(p)).join(", ") || "—"}</div>
    </td>
    <td>
      ${row.version ? h`<code>${row.version}</code>` : h`<span class="dim">none observed</span>`}
      <div class="sub">${row.version_source || ""}</div>
    </td>
    <td>
      ${row.country_code || row.country || "—"}
      <div class="sub">${row.city || ""}</div>
    </td>
    <td>
      ${row.asn || "—"}
      <div class="sub">${row.org || ""}</div>
    </td>
    <td class="cell-seen">
      <div class="sub">first ${day(row.first_seen)}</div>
      <div class="sub">last ${day(row.last_seen)}</div>
    </td>
    <td>
      ${stateChip(row.state)}
      ${row.vuln_count ? chip(`${fmt(row.vuln_count)} vuln`, "bad") : ""}
      <div class="sub">${discloseChip(row.disclosure)}</div>
    </td>
  </tr>`;
}

export function pager(page) {
  if (!page) return "";
  const from = page.total ? (page.page - 1) * page.page_size + 1 : 0;
  const to = Math.min(page.page * page.page_size, page.total);
  return h`<div class="pager">
    <button class="btn" data-page="first" ${page.page <= 1 ? "disabled" : ""}>|«</button>
    <button class="btn" data-page="prev" ${page.page <= 1 ? "disabled" : ""}>« prev</button>
    <span class="pageinfo">${fmt(from)}–${fmt(to)} of ${fmt(page.total)} · page ${fmt(page.page)} / ${fmt(page.pages)}</span>
    <button class="btn" data-page="next" ${page.has_more ? "" : "disabled"}>next »</button>
    <button class="btn" data-page="last" ${page.page >= page.pages ? "disabled" : ""}>»|</button>
  </div>`;
}

/* ------------------------------------------------------------------ */
/* Map / cross-tab view                                                */
/* ------------------------------------------------------------------ */

export function mapView(data) {
  const t = data.totals || {};
  const x = data.crosstab || {};
  return h`
    ${corpusBanner(data)}
    ${provenance(data.provenance)}
    <div class="tiles">
      ${tile(fmt(t.hosts), "hosts in view")}
      ${tile(fmt(t.host_stack_pairs), "host × stack pairs", "One host exposing two stacks counts in both buckets.")}
      ${tile(fmt(t.hosts_with_version), "with a version string")}
      ${tile(fmt(t.distinct_countries), "countries")}
      ${tile(fmt(t.distinct_asns), "ASNs")}
    </div>

    <div class="cards">
      ${barCard("by stack", data.by_stack)}
      ${barCard("by verification state", data.by_state, { note: data.state_note })}
      ${barCard("version spread", data.by_version, { mono: true })}
      ${barCard("by country", data.by_country)}
      ${barCard("by source", data.by_source)}
      ${barCard("top orgs", data.by_org)}
    </div>

    ${asnCard(data.by_asn)}

    <h3 class="section">cross-tabs</h3>
    <div class="stack">
      ${crossTabCard("stack × country", x.stack_x_country)}
      ${crossTabCard("stack × ASN", x.stack_x_asn)}
      ${crossTabCard("version × stack", x.version_x_stack)}
    </div>

    ${exposureCard(data.exposure_rate_by_stack)}
    ${timelineCard(data.timeline)}
    ${limitationsBox(data.limitations)}`;
}

/**
 * Spec §4: three provenance-tagged numbers, rendered side by side but never
 * summed and never given equal weight without their source string. Presenting
 * a counted number next to a re-verified one as if they measured the same thing
 * is the exact layout mistake spec 001 exists to correct.
 */
function provenance(p) {
  if (!p) return "";
  const card = (key, obj, note) =>
    h`<div class="prov">
      <div class="prov-key">${key.replace(/_/g, " ")}</div>
      <div class="prov-num">${fmt(obj?.hosts)}</div>
      <div class="prov-src">${obj?.source || "—"}</div>
      ${note ? h`<div class="sub">${note}</div>` : ""}
    </div>`;
  return h`<div class="prov-wrap">
    <div class="prov-row">
      ${card("archive snapshot", p.archive_snapshot)}
      ${card("indexed observed", p.indexed_observed)}
      ${card(
        "re-verified",
        p.reverified,
        p.reverified?.window_days ? `within a ${Number(p.reverified.window_days)}-day re-probe interval (I-24)` : ""
      )}
    </div>
    <p class="dim">These three numbers measure different things and are never summed. The archive count was counted, not probed; the re-verified count is bounded by what public indexes list.</p>
  </div>`;
}

function barCard(title, block, opts = {}) {
  const rows = block?.top || [];
  if (!rows.length) return h`<div class="card"><h3>${title}</h3>${empty("no data in this view")}</div>`;
  const max = rows[0]?.hosts || 1;
  return h`<div class="card">
    <h3>${title} ${block.distinct ? chip(`${fmt(block.distinct)} distinct`) : ""}</h3>
    ${rows.map(
      (r) => h`<div class="bar-row">
        <span class="bar-lbl ${opts.mono ? "mono" : ""}" title="${r.key}">${r.key}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${width(r.hosts, max)}%"></span></span>
        <span class="bar-val">${fmt(r.hosts)}</span>
      </div>`
    )}
    ${block.truncated ? h`<p class="sub">truncated — more keys than the payload cap</p>` : ""}
    ${opts.note ? h`<p class="sub">${opts.note}</p>` : ""}
  </div>`;
}

function asnCard(block) {
  const rows = block?.top || [];
  if (!rows.length) return "";
  return h`<div class="card wide">
    <h3>top ASNs ${block.distinct ? chip(`${fmt(block.distinct)} distinct`) : ""}</h3>
    <div class="table-wrap">
      <table class="grid tight">
        <thead><tr><th>ASN</th><th>hosts</th><th>org (modal)</th><th>countries</th><th>stacks</th></tr></thead>
        <tbody>
          ${rows.map(
            (r) => h`<tr>
              <td class="mono">${r.key}</td>
              <td>${fmt(r.hosts)}</td>
              <td>${r.org || "—"}</td>
              <td>${(r.countries || []).map((c) => chip(c))}</td>
              <td>${(r.stacks || []).map((s) => chip(s, "live"))}</td>
            </tr>`
          )}
        </tbody>
      </table>
    </div>
  </div>`;
}

function crossTabCard(title, tab) {
  if (!tab || !tab.rows?.length || !tab.cols?.length) {
    return h`<div class="card wide"><h3>${title}</h3>${empty("not enough data for a cross-tab in this view")}</div>`;
  }
  const cells = new Map();
  let max = 0;
  for (const c of tab.cells || []) {
    cells.set(`${c.row} ${c.col}`, c.hosts);
    if (c.hosts > max) max = c.hosts;
  }
  return h`<div class="card wide">
    <h3>${title} ${tab.truncated ? chip("truncated", "warn", "More rows or columns than the payload cap.") : ""}</h3>
    <div class="table-wrap">
      <table class="grid xtab">
        <thead>
          <tr>
            <th></th>
            ${tab.cols.map((c) => h`<th class="rot" title="${c.key} · ${fmt(c.hosts)} hosts">${c.key}</th>`)}
            <th class="total">Σ</th>
          </tr>
        </thead>
        <tbody>
          ${tab.rows.map(
            (r) => h`<tr>
              <th class="rowhead" title="${r.key}">${r.key}</th>
              ${tab.cols.map((c) => {
                const n = cells.get(`${r.key} ${c.key}`) || 0;
                return n
                  ? h`<td class="heatcell" style="background:rgba(92,225,255,${heat(n, max)})" title="${r.key} × ${c.key}">${fmt(n)}</td>`
                  : h`<td class="heatcell zero">·</td>`;
              })}
              <td class="total">${fmt(r.hosts)}</td>
            </tr>`
          )}
          <tr>
            <th class="rowhead">Σ</th>
            ${tab.cols.map((c) => h`<td class="total">${fmt(c.hosts)}</td>`)}
            <td></td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="sub">Row and column totals count host × key pairs, so they can exceed the host count.</p>
  </div>`;
}

function exposureCard(block) {
  const rows = block?.rows || [];
  return h`<div class="card wide">
    <h3>exposure rate by stack</h3>
    ${rows.length
      ? h`<div class="table-wrap">
          <table class="grid tight">
            <thead><tr><th>service</th><th>checks</th><th>detected</th><th>exposed</th><th>exposed / detected</th><th>exposed / checked</th></tr></thead>
            <tbody>
              ${rows.map(
                (r) => h`<tr>
                  <td>${chip(r.service, "live")}</td>
                  <td>${fmt(r.checks)}</td>
                  <td>${fmt(r.detected)}</td>
                  <td>${fmt(r.exposed)}</td>
                  <td>${r.exposed_of_detected == null ? "—" : pct(r.exposed_of_detected)}</td>
                  <td>${r.exposed_of_checked == null ? "—" : pct(r.exposed_of_checked)}</td>
                </tr>`
              )}
            </tbody>
          </table>
        </div>`
      : empty("no check ledger data yet")}
    <p class="sub">Denominator: ${block?.denominator || "—"}</p>
    <p class="sub">The corpus itself has no denominator: it only holds hosts that were exposed, so a rate derived from it would be 100% by construction.</p>
  </div>`;
}

function timelineCard(tl) {
  if (!tl) return "";
  const series = (title, rows) => {
    const slice = (rows || []).slice(-40);
    if (!slice.length) return h`<div class="card"><h3>${title}</h3>${empty("no dated records in this view")}</div>`;
    const max = Math.max(...slice.map((r) => Number(r.hosts) || 0), 1);
    return h`<div class="card">
      <h3>${title} <span class="sub">${tl.bucket} buckets</span></h3>
      <div class="spark">
        ${slice.map(
          (r) => h`<span class="spark-col" title="${r.bucket} · ${fmt(r.hosts)} hosts · ${fmt(r.cumulative)} cumulative">
            <span class="spark-bar" style="height:${width(r.hosts, max)}%"></span>
          </span>`
        )}
      </div>
      <div class="spark-axis"><span>${slice[0].bucket}</span><span>${slice[slice.length - 1].bucket}</span></div>
    </div>`;
  };
  return h`<div class="cards">
    ${series("first seen", tl.first_seen)}
    ${series("last seen", tl.last_seen)}
  </div>`;
}

/* ------------------------------------------------------------------ */
/* Validation view                                                     */
/* ------------------------------------------------------------------ */

export function validationView(data, opts) {
  const hosts = data.hosts || [];
  const s = data.summary || {};
  return h`
    ${corpusBanner(data)}
    <div class="tiles">
      ${tile(fmt(s.with_version), "with version")}
      ${tile(fmt(s.without_version), "without version")}
      ${tile(fmt(s.with_indexed_vulns), "with indexed vulns")}
      ${tile(fmt(s.notified), "notification attempted")}
      ${tile(fmt(s.publishable), "publishable (I-27)")}
    </div>
    ${(s.by_state || []).length
      ? h`<div class="chiprow">${(s.by_state || []).map((b) => h`${stateChip(b.key)}<span class="sub">${fmt(b.hosts)}</span>`)}</div>`
      : ""}
    ${osvBanner(data.osv)}
    ${hosts.length ? hosts.map((row, i) => validationCard(row, i, opts)) : empty("No host matches these filters.")}
    ${pager(data.page)}
    ${caveatBox("what 'confirmed' means here", data.caveats)}
    ${limitationsBox(data.limitations)}`;
}

function osvBanner(osv) {
  if (!osv) return "";
  return h`<div class="notice ${osv.truncated ? "warn" : ""}">
    <div class="notice-head">
      OSV lookups ${chip(osv.requested ? "on" : "off", osv.requested ? "live" : "")}
      ${osv.requested ? chip(`${fmt(osv.lookups_used)} / ${fmt(osv.lookup_cap)} used`) : ""}
      ${osv.truncated ? chip("cap reached", "warn") : ""}
    </div>
    <p>${osv.note}</p>
  </div>`;
}

function validationCard(row, index, opts) {
  const v = row.verification || {};
  return h`<div class="card host-card" data-ip="${row.ip}">
    <div class="host-head">
      <div>
        ${addressLabel(row.ip, index, opts.masked)}
        ${(row.stacks || []).map((s) => chip(s, "live"))}
        ${(row.ports || []).map((p) => chip(Number(p)))}
      </div>
      <div>${stateChip(v.state)} ${discloseChip(row.disclosure)}</div>
    </div>

    <div class="kv">
      <span>version observed</span>
      <span>${row.version_observed ? h`<code>${row.version_observed}</code>` : h`<span class="dim">none</span>`}
        ${row.version_source ? chip(row.version_source) : ""}</span>
      <span>last verified</span>
      <span>${stamp(v.last_success_at)} ${v.days_since_success == null ? "" : chip(`${days(v.days_since_success)} ago`)}</span>
      <span>last attempt</span>
      <span>${stamp(v.last_attempt_at)}</span>
      <span>gone silent</span>
      <span>${v.silent_since
        ? h`${stamp(v.silent_since)} ${chip("answered, then stopped", "warn")}`
        : h`<span class="dim">not observed going silent</span>`}</span>
      <span>expires</span>
      <span>${stamp(v.expires_at)} ${v.expired ? chip("past horizon", "bad") : ""}</span>
      <span>re-probe eligible</span>
      <span>${stamp(v.reprobe_eligible_at)} <span class="dim">informational — the lab never schedules or sends a probe</span></span>
    </div>

    ${findingList("confirmed findings", row.confirmed)}
    ${advisoryList("exposure-class advisories", row.advisories)}
    ${vulnList("indexed vulns", row.vulns_indexed)}
    ${vulnList("OSV matches (version-string inference)", row.osv)}
  </div>`;
}

function findingList(title, list) {
  if (!list || !list.length) return "";
  return h`<div class="block">
    <h4>${title}</h4>
    ${list.map(
      (f) => h`<div class="finding">
        <div class="finding-head">${sevChip(f.severity)} <strong>${f.title}</strong> ${chip(f.finding_id)}</div>
        <div class="sub">${f.service || "—"}${f.port ? h` · port ${Number(f.port)}` : ""} · observed ${stamp(f.observed_at)}</div>
        <p class="sub">${f.basis}</p>
      </div>`
    )}
  </div>`;
}

function advisoryList(title, list) {
  if (!list || !list.length) return "";
  return h`<div class="block">
    <h4>${title}</h4>
    ${list.map(
      (a) => h`<div class="finding">
        <div class="finding-head">${sevChip(a.severity)} <strong>${a.title}</strong> ${chip(a.id)}</div>
        ${a.remediation ? h`<p class="sub">${a.remediation}</p>` : ""}
      </div>`
    )}
  </div>`;
}

function vulnList(title, list) {
  if (!list || !list.length) return "";
  return h`<div class="block">
    <h4>${title}</h4>
    <ul class="tight">
      ${list.map(
        (v) => h`<li>
          ${sevChip(v.severity)} <code>${v.id || v.cve || "?"}</code>
          ${v.cve && v.cve !== v.id ? chip(v.cve) : ""}
          ${v.source ? chip(v.source) : ""}
          ${v.matched_on ? chip(`matched on ${v.matched_on}`) : ""}
          ${v.title ? h`<div class="sub">${v.title}</div>` : ""}
          ${(v.aliases || []).length ? h`<div class="sub">aliases: ${(v.aliases || []).join(", ")}</div>` : ""}
          ${(v.references || []).length
            ? h`<div class="sub refs">refs: ${(v.references || []).join("  ")}</div>`
            : ""}
        </li>`
      )}
    </ul>
  </div>`;
}

/* ------------------------------------------------------------------ */
/* Host detail                                                         */
/* ------------------------------------------------------------------ */

export function hostView(data, opts) {
  const host = data.host || {};
  const net = host.network || {};
  const ver = host.version || {};
  const f = data.findings || {};
  const v = data.verification || {};
  const r = data.retention || {};
  return h`
    <div class="host-detail">
      <div class="host-head">
        <div>
          ${addressLabel(host.ip, 0, opts.masked)}
          ${(host.stacks || []).map((s) => chip(s, "live"))}
          ${(host.ports || []).map((p) => chip(Number(p)))}
        </div>
        <div>${stateChip(v.state)} ${discloseChip(data.disclosure)}</div>
      </div>

      <div class="kv">
        <span>source</span><span>${host.source || "—"}</span>
        <span>first seen</span><span>${stamp(host.first_seen)}</span>
        <span>last seen</span><span>${stamp(host.last_seen)}</span>
        <span>times seen</span><span>${fmt(host.times_seen)}</span>
        <span>ASN</span><span>${net.asn || "—"}</span>
        <span>org</span><span>${net.org || "—"}</span>
        <span>geo</span><span>${[net.city, net.country, net.country_code].filter(Boolean).join(" · ") || "—"}</span>
        <span>version</span>
        <span>${ver.observed ? h`<code>${ver.observed}</code>` : h`<span class="dim">none observed</span>`}
          ${ver.source ? chip(ver.source) : ""}</span>
        <span>banner</span><span class="mono">${ver.banner || "—"}</span>
      </div>

      <div class="block">
        <h4>verification (I-24 / I-26)</h4>
        <div class="kv">
          <span>last verified</span>
          <span>${stamp(v.last_success_at)} ${v.days_since_success == null ? "" : chip(`${days(v.days_since_success)} ago`)}</span>
          <span>last attempt</span>
          <span>${stamp(v.last_attempt_at)} ${v.days_since_attempt == null ? "" : chip(`${days(v.days_since_attempt)} ago`)}</span>
          <span>gone silent</span>
          <span>${v.silent_since ? h`${stamp(v.silent_since)} ${chip("answered, then stopped", "warn")}` : h`<span class="dim">not observed going silent</span>`}</span>
          <span>expires</span>
          <span>${stamp(v.expires_at)} ${v.expired ? chip("past horizon", "bad") : ""}</span>
          <span>re-probe eligible</span>
          <span>${stamp(v.reprobe_eligible_at)}</span>
        </div>
        <p class="sub">${v.basis || ""}</p>
      </div>

      ${findingList("confirmed findings", f.confirmed)}
      ${advisoryList("exposure-class advisories", f.advisories)}
      ${vulnList("indexed vulns", f.vulns_indexed)}
      ${vulnList("OSV matches", f.osv)}

      <div class="block">
        <h4>models retained on this record</h4>
        <p class="sub">${fmt(host.models_count)} recorded. Model lists are not part of the record we intend to retain (I-26), so names are opt-in and capped.</p>
        ${host.models
          ? h`<ul class="tight">${host.models.map((m) => h`<li><code>${m}</code></li>`)}</ul>`
          : host.models_count
            ? h`<button class="btn" id="load-models">show model names (I-26 opt-in)</button>`
            : ""}
      </div>

      <div class="block">
        <h4>retention (I-26)</h4>
        <div class="kv">
          <span>expires at</span><span>${stamp(r.expires_at)}</span>
          <span>policy</span><span>${fmt(r.policy_days)} days from last successful contact</span>
          <span>retained fields</span><span>${(r.retained_fields || []).map((x) => chip(x))}</span>
        </div>
        <p class="sub">${r.note || ""}</p>
      </div>

      <div class="block">
        <h4>disclosure (I-27)</h4>
        <div class="kv">
          <span>notified at</span><span>${stamp(data.disclosure?.notified_at)}</span>
          <span>route</span><span>${data.disclosure?.notified_via || "—"}</span>
          <span>window</span><span>${fmt(data.disclosure?.window_days)} days</span>
          <span>publishable at</span><span>${stamp(data.disclosure?.publishable_at)}</span>
          <span>status</span><span>${discloseChip(data.disclosure)} <span class="sub">${data.disclosure?.reason || ""}</span></span>
        </div>
      </div>

      ${(data.remediation || []).length
        ? h`<div class="block">
            <h4>remediation to hand the operator</h4>
            <ul class="tight">${data.remediation.map((x) => h`<li>${x}</li>`)}</ul>
          </div>`
        : ""}

      <div class="notice">
        <div class="notice-head">read-only by construction</div>
        <p>Everything above is read back from a stored record. The lab never contacts this host: no re-test, no link, no embed, no relay (I-3, I-20). Impact is described, never demonstrated.</p>
      </div>
    </div>`;
}
