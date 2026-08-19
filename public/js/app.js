/* global LEAKY_CONFIG */
(function () {
  const cfg = window.LEAKY_CONFIG || {};
  const $ = (id) => document.getElementById(id);

  function stamp(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    // UTC on purpose: a timestamp that shifts with the reader's timezone is not
    // a citable snapshot.
    return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString("en-US");
  }

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[c]);
  }

  let lastGeo = [];
  let lastCountryStack = {};

  // Regional-indicator pair from the ISO code — no flag assets to ship, and it
  // degrades to the letters themselves on platforms without the glyphs.
  function flagFor(cc) {
    const c = String(cc || "").toUpperCase();
    if (!/^[A-Z]{2}$/.test(c)) return "\u{1F3F3}";
    return String.fromCodePoint(
      0x1f1e6 + c.charCodeAt(0) - 65,
      0x1f1e6 + c.charCodeAt(1) - 65
    );
  }

  // Intl gives us every country name the browser already knows, so there is no
  // code->name table to ship or keep current.
  const REGION_NAMES = (() => {
    try {
      return new Intl.DisplayNames(["en"], { type: "region" });
    } catch {
      return null;
    }
  })();

  function countryName(cc) {
    const c = String(cc || "").toUpperCase();
    if (c === "ZZ" || !/^[A-Z]{2}$/.test(c)) return "Unattributed";
    try {
      return REGION_NAMES?.of(c) || c;
    } catch {
      return c;
    }
  }

  function stackSummary(cc) {
    const stacks = lastCountryStack[String(cc || "").toUpperCase()];
    if (!stacks) return "";
    const parts = Object.entries(stacks)
      .filter(([, n]) => n > 0)
      .sort((a, b) => b[1] - a[1]);
    if (!parts.length) return "";
    return parts.map(([k, n]) => `${k} ${n}`).join(" · ");
  }

  function renderGeo(rows, sortMode) {
    const el = $("geo-list");
    if (!rows || !rows.length) {
      el.textContent = "No geo data yet — run multi-lane discovery ingest.";
      return;
    }
    const sorted = rows.slice();
    if (sortMode === "name") {
      sorted.sort((a, b) =>
        countryName(a.country).localeCompare(countryName(b.country))
      );
    } else {
      sorted.sort((a, b) => (b.count || 0) - (a.count || 0));
    }
    const max = Math.max(...sorted.map((r) => r.count || 0), 1);

    el.innerHTML = sorted
      .slice(0, 40)
      .map((r) => {
        const cc = r.country || "??";
        const n = r.count || 0;
        const pct = ((n / max) * 100).toFixed(0);
        const name = countryName(cc);
        const detail = stackSummary(cc);
        // I-16: every one of these came from a probed host's metadata.
        const title = esc(
          detail
            ? `${name} — ${n} exposed host${n === 1 ? "" : "s"}\n${detail}`
            : `${name} — ${n} exposed host${n === 1 ? "" : "s"}`
        );
        return (
          `<div class="geo-row" tabindex="0" title="${title}" ` +
          `aria-label="${title}">` +
          `<span class="geo-flag" aria-hidden="true">${flagFor(cc)}</span>` +
          `<span class="geo-cc">${esc(cc)}</span>` +
          `<span class="geo-bar"><span style="width:${pct}%"></span></span>` +
          `<span class="geo-n">${fmt(n)}</span>` +
          `<span class="geo-pop"><strong>${esc(name)}</strong>` +
          (detail ? `<span class="geo-pop-detail">${esc(detail)}</span>` : "") +
          `</span>` +
          `</div>`
        );
      })
      .join("");
  }

  async function loadStats() {
    const snapVal = $("snap-hosts");
    const liveVal = $("live-exposed");
    const snapSub = $("snap-sub");
    const liveSub = $("live-sub");
    const apiNote = $("api-note");

    // fallback first
    snapVal.textContent = fmt(cfg.SNAPSHOT_FALLBACK?.hosts);
    liveVal.textContent = "—";

    try {
      const res = await fetch(`${cfg.API_BASE}/v1/stats`, { credentials: "omit" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      // Archive
      snapVal.textContent = fmt(data.archive_snapshot?.hosts ?? data.research_snapshot?.hosts);
      $("snap-models").textContent = fmt(
        data.archive_snapshot?.models ?? data.research_snapshot?.models
      );
      snapSub.textContent =
        data.archive_snapshot?.note || "Archive-era filtered seed. Not re-verified.";

      // Shodan snapshot — timestamped, because "indexed now" is only meaningful
      // with a "now" attached to it.
      const idx = data.indexed_observed || {};
      $("indexed-hosts").textContent = fmt(idx.hosts);
      $("indexed-sub").textContent =
        idx.note || "Counted from public index records. We sent these hosts nothing.";
      $("indexed-stamp").textContent = idx.last_observed_at
        ? `as of ${stamp(idx.last_observed_at)}`
        : "as of —";

      // Confirmed exposed
      const rev = data.reverified || {};
      // Distinct hosts, not observations. exposed_total is cumulative and counts
      // a host once per run it answered in, so it drifts above the number of
      // machines that exist — fine as a secondary figure, wrong as the headline
      // under a claim that says "confirmed exposed".
      liveVal.textContent = fmt(rev.hosts);
      $("live-observations").textContent = fmt(data.live_instrumented?.exposed_total);
      $("live-checks").textContent = fmt(data.live_instrumented?.checks_total);
      liveSub.textContent = "Distinct hosts we re-verified with a read-only GET.";
      $("confirmed-asof").textContent = stamp(
        rev.last_reverified_at || data.live_instrumented?.last_check_at || data.updated_at
      );

      apiNote.textContent = `API ok · updated ${stamp(data.updated_at) || "—"}`;
      apiNote.dataset.state = "ok";

      lastGeo = data.geography?.by_country || [];
      lastCountryStack = data.geography?.by_country_stack || {};
      $("geo-note").textContent =
        data.geography?.note || "Unique re-verified hosts · sorted · no raw IPs";
      renderGeo(lastGeo, $("geo-sort").value);
    } catch (err) {
      apiNote.textContent =
        "API offline or not configured — showing snapshot fallback. Set public/js/config.js API_BASE after deploy.";
      apiNote.dataset.state = "err";
      snapSub.textContent = "Local snapshot fallback (seed).";
      liveSub.textContent = "Connect API to accumulate live counts.";
    }
  }

  // Report content includes strings echoed from the probed host (versions,
  // model names). In override mode that host is attacker-controlled, so
  // everything interpolated into markup goes through here first.
  const SEV_LABEL = {
    critical: "CRITICAL",
    high: "HIGH",
    medium: "MEDIUM",
    low: "LOW",
    info: "INFO",
    none: "CLEAR",
  };

  function renderServiceCard(s) {
    const state = s.exposed
      ? "exposed"
      : s.detected
      ? "detected"
      : "clear";
    const stateText = s.exposed
      ? "EXPOSED"
      : s.detected
      ? s.authenticated
        ? "reachable · auth enforced"
        : "reachable"
      : "not detected";

    const rows = [];
    rows.push(
      `<div class="svc-head"><span class="svc-name">${esc(s.label || s.service)}</span>` +
        `<span class="svc-port">:${esc(s.port)}</span>` +
        `<span class="svc-state ${state}">${esc(stateText)}</span></div>`
    );
    if (s.version) {
      rows.push(`<div class="svc-meta">version ${esc(s.version)}</div>`);
    }
    if (!s.detected) {
      rows.push(
        `<div class="svc-meta dim">No response on this port (${esc(
          s.error || "no service"
        )}).</div>`
      );
      return `<div class="svc ${state}">${rows.join("")}</div>`;
    }

    for (const f of s.findings || []) {
      rows.push(
        `<div class="finding sev-${esc(f.severity)}">` +
          `<div class="finding-head"><span class="sev">${esc(
            SEV_LABEL[f.severity] || f.severity
          )}</span> ${esc(f.title)}</div>` +
          `<div class="finding-detail">${esc(f.detail)}</div>` +
          (f.endpoint
            ? `<div class="finding-ep">evidence: <code>GET ${esc(f.endpoint)}</code></div>`
            : "") +
          `</div>`
      );
    }

    if (s.models?.length) {
      const names = s.models.slice(0, 10).map((m) => `<li>${esc(m.name)}</li>`).join("");
      rows.push(
        `<div class="svc-meta">models visible (${s.models.length}):<ul class="models">${names}</ul></div>`
      );
    }
    if (typeof s.jobs_visible === "number") {
      rows.push(`<div class="svc-meta">jobs visible: ${esc(s.jobs_visible)}</div>`);
    }

    if (s.exposed && s.remediation?.length) {
      const items = s.remediation.map((r) => `<li>${esc(r)}</li>`).join("");
      rows.push(`<div class="remediation"><strong>Fix</strong><ul>${items}</ul></div>`);
    }

    return `<div class="svc ${state}">${rows.join("")}</div>`;
  }

  function renderReport(data) {
    const verdict = $("verdict");
    const report = $("report");
    const sev = data.overall_severity || "none";

    verdict.hidden = false;
    verdict.className = `verdict sev-${sev}`;
    verdict.innerHTML =
      `<div class="verdict-line">${
        data.any_exposed
          ? "&#9888; EXPOSED — an AI service answered an unauthenticated read"
          : "&#10003; No exposed AI service observed"
      }</div>` +
      `<div class="verdict-sub">target ${esc(data.target)} · severity ${esc(
        SEV_LABEL[sev] || sev
      )} · ${esc(data.checked_at || "")}</div>`;

    report.innerHTML = (data.services || []).map(renderServiceCard).join("");

    const out = $("result");
    out.className = "result";
    out.textContent = [data.guidance, "", data.limitations]
      .filter(Boolean)
      .join("\n");
  }

  async function runCheck() {
    const out = $("result");
    const btn = $("check-btn");
    const override = $("override-toggle").checked;
    const target = $("target-input").value.trim();
    const authorized = $("auth-check").checked;

    $("verdict").hidden = true;
    $("report").innerHTML = "";
    out.className = "result";
    out.textContent = "probing Ollama, Ray and Jupyter…";
    btn.disabled = true;

    const body = {};
    if (override) {
      body.target = target;
      body.authorized = authorized;
    }
    // Turnstile token hook
    if (window.turnstileToken) body.turnstile_token = window.turnstileToken;

    try {
      const res = await fetch(`${cfg.API_BASE}/v1/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        out.classList.add("exposed");
        out.textContent = `${data.error || "request failed"}${
          data.message ? `\n${data.message}` : ""
        }`;
        return;
      }
      renderReport(data);
      loadStats();
    } catch (err) {
      out.classList.add("exposed");
      out.textContent = `Request failed: ${err}\nIs API_BASE set in config.js?`;
    } finally {
      btn.disabled = false;
    }
  }

  function wireUi() {
    const dontPanic = cfg.DONT_PANIC_URL || "https://mahdihedhli.com/dont-panic/";
    if ($("dont-panic-link")) $("dont-panic-link").href = dontPanic;
    if ($("dont-panic-eyebrow")) $("dont-panic-eyebrow").href = dontPanic;
    $("repo-link").href = cfg.REPO_URL;
    $("lab-link").href = cfg.LAB_URL;
    $("access-link").href = cfg.ACCESS_ISSUE_URL;

    const ov = $("override-toggle");
    const block = $("override-fields");
    ov.addEventListener("change", () => {
      block.hidden = !ov.checked;
    });

    $("check-btn").addEventListener("click", runCheck);
    $("refresh-stats").addEventListener("click", loadStats);
    $("geo-sort").addEventListener("change", () =>
      renderGeo(lastGeo, $("geo-sort").value)
    );
  }

  wireUi();
  loadStats();
  setInterval(loadStats, 120000);
})();
