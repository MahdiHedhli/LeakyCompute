/* global LEAKY_LAB_CONFIG */
(function () {
  const cfg = window.LEAKY_LAB_CONFIG || {};
  const $ = (id) => document.getElementById(id);

  let allModels = [];
  let view = [];
  let sortKey = "num";
  let sortDir = "desc";
  let identity = null;

  const listEl = $("model-list");
  const searchEl = $("search");
  const clearEl = $("search-clear");
  const appEl = $("app");

  function fmt(n) {
    return Number(n || 0).toLocaleString("en-US");
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  function highlight(text, q) {
    if (!q) return escapeHtml(text);
    const i = text.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return escapeHtml(text);
    return (
      escapeHtml(text.slice(0, i)) +
      "<mark>" +
      escapeHtml(text.slice(i, i + q.length)) +
      "</mark>" +
      escapeHtml(text.slice(i + q.length))
    );
  }

  function animateCount(el, target) {
    const dur = 1200;
    let start = null;
    function step(ts) {
      if (start === null) start = ts;
      const p = Math.min((ts - start) / dur, 1);
      el.textContent = fmt(Math.round((1 - Math.pow(1 - p, 3)) * target));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  async function api(path, opts = {}) {
    const headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    if (cfg.DEV_GITHUB_LOGIN) headers["X-Dev-GitHub-Login"] = cfg.DEV_GITHUB_LOGIN;
    // Access JWT is injected by CF on same-zone requests when Access is configured.
    const res = await fetch(`${cfg.API_BASE}${path}`, {
      ...opts,
      headers,
      credentials: "include",
    });
    const data = await res.json().catch(() => ({}));
    return { res, data };
  }

  async function checkAccess() {
    const box = $("auth-box");
    try {
      const { res, data } = await api("/v1/research/me");
      identity = data;
      if (data.allowed) {
        box.className = "auth-box good";
        box.innerHTML = `<strong>Access granted</strong> · @${escapeHtml(
          data.login || "?"
        )} · catalog unlocked · chat deferred (phase B)`;
        appEl.classList.remove("sb-hidden");
        return true;
      }
      if (data.authenticated) {
        box.className = "auth-box bad";
        box.innerHTML = `<strong>Authenticated but not allowlisted</strong> · @${escapeHtml(
          data.login || "?"
        )}. <a href="${cfg.ACCESS_ISSUE_URL}" target="_blank" rel="noopener">Request access</a>.`;
        return false;
      }
      box.className = "auth-box";
      box.innerHTML = `<strong>Lab gate</strong> · Sign in with GitHub via Cloudflare Access (when deployed), or use local dev <code>?dev_user=you</code> against wrangler. <a href="${cfg.ACCESS_ISSUE_URL}" target="_blank" rel="noopener">Request access</a>.`;
      // Still show seed catalog read-only? Plan said gated — hide list until allowed.
      return false;
    } catch (err) {
      box.className = "auth-box";
      box.innerHTML = `<strong>API unreachable</strong> · set lab/js/config.js API_BASE. Showing seed offline for UI review. (${escapeHtml(
        String(err.message || err)
      )})`;
      // Offline demo mode for UI polish
      appEl.classList.remove("sb-hidden");
      return true;
    }
  }

  async function loadSeed() {
    const res = await fetch(cfg.SEED_URL);
    const seed = await res.json();
    allModels = (seed.models || []).map((m) => ({
      model: m.model,
      hosts: m.hosts || 0,
      size: m.size || "?",
      num: m.num || 0,
      validated: !!m.validated,
      source: m.source || "archive_seed",
      seen: m.seen || null,
    }));
    const hosts = allModels.reduce((n, m) => n + (m.hosts || 0), 0);
    animateCount($("c-models"), allModels.length);
    animateCount($("c-nodes"), hosts);
    apply();
  }

  function apply() {
    const q = searchEl.value.trim().toLowerCase();
    clearEl.hidden = !q;
    view = allModels.filter((m) => !q || m.model.toLowerCase().includes(q));
    view.sort((a, b) => {
      let d;
      if (sortKey === "model") d = a.model.localeCompare(b.model);
      else if (sortKey === "hosts") d = a.hosts - b.hosts;
      else d = (a.num || 0) - (b.num || 0);
      return sortDir === "asc" ? d : -d;
    });
    renderList(q);
  }

  function renderList(q) {
    listEl.innerHTML = "";
    const frag = document.createDocumentFragment();
    // virtualize lightly: first 500 for free-tier browser sanity
    view.slice(0, 500).forEach((m) => {
      const li = document.createElement("li");
      li.className = "mrow";
      li.innerHTML =
        `<span class="name">${highlight(m.model, q)}</span>` +
        `<span class="meta">` +
        `<span class="chip">${escapeHtml(String(m.size))}</span>` +
        `<span class="chip live">${fmt(m.hosts)} nodes</span>` +
        `<span class="chip ${m.validated ? "ok" : "warn"}">${
          m.validated ? "validated" : "seed"
        }</span>` +
        `</span>`;
      li.onclick = () => openCase(m, li);
      frag.appendChild(li);
    });
    if (view.length > 500) {
      const more = document.createElement("li");
      more.className = "mrow";
      more.innerHTML = `<span class="name" style="color:var(--dim)">… ${
        view.length - 500
      } more — refine search</span>`;
      frag.appendChild(more);
    }
    listEl.appendChild(frag);
  }

  function openCase(m, li) {
    document.querySelectorAll(".mrow").forEach((el) => el.classList.remove("active"));
    if (li) li.classList.add("active");
    $("welcome").hidden = true;
    $("session").hidden = false;
    if (window.innerWidth <= 720) appEl.classList.add("sb-hidden");
    $("ch-name").textContent = m.model;
    $("ch-size").textContent = m.size;
    $("ch-valid").textContent = m.validated ? "validated" : "seed";
    $("ch-valid").className = "chip " + (m.validated ? "ok" : "warn");
    $("pool-info").textContent = "lab mode · no third-party proxy · chat locked";
    $("detail").innerHTML = `
      <h3>CASE FILE</h3>
      <p><strong>model</strong> <code>${escapeHtml(m.model)}</code></p>
      <p><strong>seed hosts</strong> ${fmt(m.hosts)}</p>
      <p><strong>size</strong> ${escapeHtml(String(m.size))}</p>
      <p><strong>source</strong> ${escapeHtml(m.source)}</p>
      <p><strong>last seen (archive)</strong> ${escapeHtml(m.seen || "n/a")}</p>
      <h3>STATUS</h3>
      <p>${
        m.validated
          ? "Confirmed by a live instrumented probe in our pipeline."
          : "Archive seed only — will be removed if it never validates in our scans."
      }</p>
      <h3>CHAT</h3>
      <p>Phase B (post-lockdown): session proxy only to allowlisted lab backends you control. STOLEN COMPUTE–style random internet proxy is intentionally not implemented.</p>
    `;
  }

  function renderStats() {
    const hosts = allModels.reduce((n, m) => n + (m.hosts || 0), 0);
    const validated = allModels.filter((m) => m.validated).length;
    $("tiles").innerHTML =
      tile(fmt(allModels.length), "seed models") +
      tile(fmt(hosts), "seed host-sum") +
      tile(fmt(validated), "validated");

    // size buckets
    const buckets = Object.create(null);
    allModels.forEach((m) => {
      const k = String(m.size || "?");
      buckets[k] = (buckets[k] || 0) + (m.hosts || 0);
    });
    const sizes = Object.entries(buckets)
      .map(([label, h]) => ({ label, hosts: h }))
      .sort((a, b) => b.hosts - a.hosts)
      .slice(0, 12);
    const total = sizes.reduce((s, x) => s + x.hosts, 0) || 1;
    const colors = ["#5ce1ff", "#f5c542", "#3ddc97", "#ff6b6b", "#a78bfa", "#f472b6", "#94a3b8"];
    $("donut-legend").innerHTML = sizes
      .map(
        (s, i) =>
          `<li><span class="sw" style="background:${colors[i % colors.length]}"></span>` +
          `<span>${escapeHtml(s.label)}</span>` +
          `<span style="margin-left:auto">${fmt(s.hosts)} · ${(
            (s.hosts / total) *
            100
          ).toFixed(0)}%</span></li>`
      )
      .join("");

    const top = [...allModels].sort((a, b) => b.hosts - a.hosts).slice(0, 12);
    const max = Math.max(...top.map((t) => t.hosts), 1);
    $("bars").innerHTML = top
      .map(
        (t) =>
          `<div class="bar-row"><span class="bar-lbl" title="${escapeHtml(
            t.model
          )}">${escapeHtml(t.model)}</span>` +
          `<span class="bar-track"><span class="bar-fill" style="width:${(
            (t.hosts / max) *
            100
          ).toFixed(1)}%"></span></span>` +
          `<span class="bar-val">${fmt(t.hosts)}</span></div>`
      )
      .join("");
  }

  function tile(val, lbl) {
    return `<div class="tile"><div class="val">${escapeHtml(val)}</div><div class="lbl">${escapeHtml(
      lbl
    )}</div></div>`;
  }

  // wire controls
  searchEl.oninput = apply;
  clearEl.onclick = () => {
    searchEl.value = "";
    apply();
    searchEl.focus();
  };
  $("collapse-btn").onclick = () => appEl.classList.add("sb-hidden");
  $("expand-btn").onclick = () => appEl.classList.remove("sb-hidden");
  $("sb-backdrop").onclick = () => appEl.classList.add("sb-hidden");
  $("stats-btn").onclick = () => {
    const modal = $("stats-modal");
    if (!modal.hidden) {
      modal.hidden = true;
      $("stats-btn").classList.remove("on");
      return;
    }
    renderStats();
    modal.hidden = false;
    $("stats-btn").classList.add("on");
  };
  $("stats-close").onclick = () => {
    $("stats-modal").hidden = true;
    $("stats-btn").classList.remove("on");
  };
  $("stats-modal").querySelector(".modal-backdrop").onclick = $("stats-close").onclick;

  document.querySelectorAll("#sort-key button").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll("#sort-key button").forEach((b) => b.classList.remove("on"));
      btn.classList.add("on");
      sortKey = btn.dataset.key;
      apply();
    };
  });
  document.querySelectorAll("#sort-dir button").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll("#sort-dir button").forEach((b) => b.classList.remove("on"));
      btn.classList.add("on");
      sortDir = btn.dataset.dir;
      apply();
    };
  });

  (async function boot() {
    const ok = await checkAccess();
    if (ok) await loadSeed();
  })();
})();
