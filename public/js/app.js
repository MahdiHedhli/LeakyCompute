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

  async function runCheck() {
    const out = $("result");
    const btn = $("check-btn");
    const override = $("override-toggle").checked;
    const target = $("target-input").value.trim();
    const port = $("port-input").value.trim() || "11434";
    const authorized = $("auth-check").checked;

    out.className = "result";
    out.textContent = "probing…";
    btn.disabled = true;

    const body = { port: Number(port) };
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
        out.textContent = JSON.stringify(data, null, 2);
        return;
      }
      out.classList.add(data.exposed ? "exposed" : "safe");
      const lines = [
        data.exposed ? "⚠ EXPOSED — unauthenticated /api/ps responded" : "✓ No open /api/ps observed",
        `mode: ${data.mode}`,
        `target: ${data.target}:${data.port}`,
        `latency: ${data.latency_ms}ms`,
        data.guidance || "",
      ];
      if (data.models?.length) {
        lines.push("models:");
        data.models.slice(0, 10).forEach((m) => lines.push(`  · ${m.name}`));
      }
      out.textContent = lines.filter(Boolean).join("\n");
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
