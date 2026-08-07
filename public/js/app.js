/* global LEAKY_CONFIG */
(function () {
  const cfg = window.LEAKY_CONFIG || {};
  const $ = (id) => document.getElementById(id);

  function fmt(n) {
    return Number(n || 0).toLocaleString("en-US");
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
        "Voluntary self-checks + researcher-owned scans.";
      apiNote.textContent = `API ok · updated ${data.updated_at || "—"}`;
      apiNote.dataset.state = "ok";
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
  }

  wireUi();
  loadStats();
  setInterval(loadStats, 120000);
})();
