/** Optional Cloudflare Turnstile verification (free). */
export async function verifyTurnstile(env, token, ip) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    // Dev / not configured: allow but mark
    return { ok: true, skipped: true };
  }
  if (!token) return { ok: false, error: "turnstile_missing" };
  try {
    const body = new URLSearchParams();
    body.set("secret", secret);
    body.set("response", token);
    if (ip) body.set("remoteip", ip);
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
    });
    const data = await resp.json();
    return { ok: !!data.success, skipped: false, codes: data["error-codes"] || [] };
  } catch {
    return { ok: false, error: "turnstile_error" };
  }
}
