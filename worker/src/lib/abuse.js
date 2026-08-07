import { hashIp } from "./hash.js";

/**
 * Private abuse / audit log. Stored only in KV under abuse:* keys.
 * Never exposed via public API. Retention via short TTL (default 14 days).
 */
export async function logAbuse(env, event) {
  if (!env.KV) return;
  try {
    const salt = env.ABUSE_LOG_SALT || "dev-salt-change-me";
    const clientHash = await hashIp(event.clientIp, salt);
    const targetHash = event.target
      ? await hashIp(String(event.target), salt)
      : null;
    const entry = {
      ts: new Date().toISOString(),
      action: event.action,
      result: event.result || null,
      client_hash: clientHash,
      target_hash: targetHash,
      reason: event.reason || null,
      override: !!event.override,
      meta: event.meta || null,
    };
    // Append-ish: one key per event (write budget: only log meaningful events)
    const id = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
    await env.KV.put(`abuse:${id}`, JSON.stringify(entry), {
      expirationTtl: 60 * 60 * 24 * 14, // 14 days
    });
  } catch {
    // never fail the request because of logging
  }
}
