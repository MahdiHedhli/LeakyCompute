/**
 * KV-backed rate limits. Designed for free-tier write budgets:
 * we update compact counters, not full request logs.
 */
export async function consume(env, key, limit, windowSec) {
  if (!env.KV) {
    return { ok: true, remaining: limit, reset: 0 };
  }
  const now = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(now / windowSec);
  const kvKey = `rl:${key}:${bucket}`;
  const raw = await env.KV.get(kvKey);
  const count = raw ? parseInt(raw, 10) || 0 : 0;
  if (count >= limit) {
    return {
      ok: false,
      remaining: 0,
      reset: (bucket + 1) * windowSec,
      limit,
    };
  }
  // Prefer eventual consistency; free tier write limit is the real constraint
  await env.KV.put(kvKey, String(count + 1), { expirationTtl: windowSec + 60 });
  return {
    ok: true,
    remaining: Math.max(0, limit - count - 1),
    reset: (bucket + 1) * windowSec,
    limit,
  };
}

export function intEnv(env, name, fallback) {
  const v = parseInt(env[name], 10);
  return Number.isFinite(v) ? v : fallback;
}
