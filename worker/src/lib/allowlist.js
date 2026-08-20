/**
 * Researcher allowlist.
 *
 * Keyed by GitHub login, because that is what the approval issue carries — but
 * matched against every identity string the Access assertion presents, because
 * the assertion may not carry a GitHub login at all. An approved researcher
 * whose email prefix differs from their GitHub handle was being rejected with
 * no way to see why; the entry now records its aliases so either name resolves.
 */

export function allowKey(login) {
  return `allowlist:github:${String(login || "").toLowerCase()}`;
}

export async function isAllowed(env, login) {
  return !!(await matchAllowEntry(env, [login]));
}

/**
 * Find the entry matching any of the identities an assertion presented.
 * Returns the entry and the name that matched, so callers can say which one.
 */
export async function matchAllowEntry(env, candidates) {
  if (!env.KV || !Array.isArray(candidates)) return null;
  for (const c of candidates) {
    if (!c) continue;
    const row = await env.KV.get(allowKey(c), "json");
    if (row && row.active !== false) return { entry: row, matched: String(c).toLowerCase() };
  }
  return null;
}

export async function getAllowEntry(env, login) {
  if (!login || !env.KV) return null;
  return env.KV.get(allowKey(login), "json");
}

export async function approveResearcher(env, { login, issue, approved_by, meta, aliases }) {
  const user = String(login || "").toLowerCase().replace(/^@/, "");
  if (!/^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$/i.test(user)) {
    throw new Error("invalid_github_login");
  }
  // An email is a legitimate alias — it is what several Access IdP
  // configurations actually assert — but only the full address and its local
  // part, never an arbitrary string, so approving one person cannot quietly
  // admit another.
  const alias = [];
  for (const a of aliases || []) {
    const v = String(a || "").trim().toLowerCase().replace(/^@/, "");
    if (!v || v === user) continue;
    const emailish = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
    const handleish = /^[a-z0-9][a-z0-9._-]{0,63}$/.test(v);
    if (emailish || handleish) alias.push(v);
  }

  const entry = {
    login: user,
    aliases: alias,
    active: true,
    issue_number: issue || null,
    approved_by: approved_by || null,
    approved_at: new Date().toISOString(),
    meta: meta || null,
  };
  await env.KV.put(allowKey(user), JSON.stringify(entry));
  // Alias keys point at the same entry, so a lookup by email resolves exactly
  // as a lookup by handle does — and revoking the primary revokes them with it.
  for (const a of alias) {
    await env.KV.put(allowKey(a), JSON.stringify({ ...entry, alias_of: user }));
  }
  return entry;
}

export async function revokeResearcher(env, login) {
  const user = String(login || "").toLowerCase().replace(/^@/, "");
  const existing = await getAllowEntry(env, user);
  // Revoking must take the aliases with it, or a revoked researcher keeps a
  // second door.
  for (const a of existing?.aliases || []) {
    const row = await env.KV.get(allowKey(a), "json");
    if (row) await env.KV.put(allowKey(a), JSON.stringify({ ...row, active: false, revoked_at: new Date().toISOString() }));
  }
  if (!existing) {
    await env.KV.delete(allowKey(user));
    return { login: user, active: false };
  }
  const entry = {
    ...existing,
    active: false,
    revoked_at: new Date().toISOString(),
  };
  await env.KV.put(allowKey(user), JSON.stringify(entry));
  return entry;
}
