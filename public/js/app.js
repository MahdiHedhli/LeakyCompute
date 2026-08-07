/* global LEAKY_CONFIG */
(function () {
  const cfg = window.LEAKY_CONFIG || {};
  const $ = (id) => document.getElementById(id);

  function fmt(n) {
    return Number(n || 0).toLocaleString("en-US");
  }

  let lastGeo = [];

  function renderGeo(rows, sortMode) {
    const el = $("geo-list");
    if (!rows || !rows.length) {
      el.textContent = "No geo data yet — run multi-lane discovery ingest.";
      return;
    }
    const sorted = rows.slice();
    if (sortMode === "name") {
      sorted.sort((a, b) =>
        String(a.country || "").localeCompare(String(b.country || ""))
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
        return (
          `<div style="display:grid;grid-template-columns:48px 1fr 40px;gap:8px;align-items:center;margin:4px 0;font-size:12px">` +
          `<span style="color:var(--cyan)">${cc}</span>` +
          `<span style="background:var(--panel2);border-radius:4px;height:8px;overflow:hidden">` +
          `<span style="display:block;height:100%;width:${pct}%;background:linear-gradient(90deg,var(--cyan),var(--amber))"></span></span>` +
          `<span style="text-align:right;color:var(--dim)">${fmt(n)}</span></div>`
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
      snapVal.textContent = fmt(data.research_snapshot?.hosts);
      $("snap-models").textContent = fmt(data.research_snapshot?.models);
      liveVal.textContent = fmt(data.live_instrumented?.exposed_total);
      $("live-checks").textContent = fmt(data.live_instrumented?.checks_total);
      snapSub.textContent =
        data.research_snapshot?.note || "Archive-era filtered seed.";
      liveSub.textContent =
        data.live_instrumented?.note ||
        "Voluntary self-checks + multi-lane discovery.";
      apiNote.textContent = `API ok · updated ${data.updated_at || "—"}`;
      apiNote.dataset.state = "ok";
      lastGeo = data.geography?.by_country || [];
      $("geo-note").textContent =
        data.geography?.note ||
        "Unique re-verified hosts · sorted · no raw IPs";
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
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[c]);
  }

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
