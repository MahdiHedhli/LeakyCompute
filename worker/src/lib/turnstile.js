/** Cloudflare Turnstile verification for the public hosted self-check. */
export async function verifyTurnstile(env, token) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    if (env.ENVIRONMENT === "production") {
      return { ok: false, error: "turnstile_not_configured" };
    }
    // Local tests and development may explicitly run without the service.
    return { ok: true, skipped: true };
  }
  if (!token) return { ok: false, error: "turnstile_missing" };
  const expectedHostname = String(env.TURNSTILE_EXPECTED_HOSTNAME || "")
    .trim()
    .toLowerCase();
  if (!expectedHostname) {
    return { ok: false, error: "turnstile_not_configured" };
  }
  try {
    const body = new URLSearchParams();
    body.set("secret", secret);
    body.set("response", token);
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
    });
    const data = await resp.json();
    const hostname = String(data.hostname || "").trim().toLowerCase();
    const action = String(data.action || "");
    const ok =
      data.success === true &&
      hostname === expectedHostname &&
      action === "hosted_self_check";
    const error = ok
      ? undefined
      : data.success !== true
        ? "turnstile_rejected"
        : hostname !== expectedHostname
          ? "turnstile_hostname_mismatch"
          : "turnstile_action_mismatch";
    const codes = Array.isArray(data["error-codes"])
      ? data["error-codes"].filter((code) => typeof code === "string").slice(0, 4)
      : [];
    if (!ok) {
      console.warn(JSON.stringify({
        event: "turnstile_verification_failed",
        reason: error,
        codes,
      }));
    }
    return {
      ok,
      skipped: false,
      codes,
      error,
    };
  } catch {
    console.warn(JSON.stringify({
      event: "turnstile_verification_failed",
      reason: "turnstile_error",
      codes: [],
    }));
    return { ok: false, error: "turnstile_error" };
  }
}
