/**
 * Researcher allowlist.
 *
 * Keyed by GitHub login, because that is what the approval issue carries — but
 * production Access presents an exact signed email rather than a GitHub login.
 * The entry therefore records approved email aliases; mutable display claims
 * and email local-parts are never treated as identities.
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
    if (!row || row.active === false) continue;
    if (row.alias_of) {
      const primary = await env.KV.get(allowKey(row.alias_of), "json");
      const candidate = String(c).trim().toLowerCase().replace(/^@/, "");
      if (!primary || primary.active === false ||
          !Array.isArray(primary.aliases) || !primary.aliases.includes(candidate)) continue;
      return { entry: primary, matched: candidate };
    }
    return { entry: row, matched: String(c).toLowerCase() };
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
  // Only a full email is a production identity alias. Arbitrary strings and
  // email local-parts would create cross-account collision opportunities.
  const alias = [];
  for (const a of aliases || []) {
    const v = String(a || "").trim().toLowerCase().replace(/^@/, "");
    if (!v || v === user) continue;
    const emailish = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
    if (emailish && !alias.includes(v)) alias.push(v);
  }

  // Resolve every ownership conflict before the first write. A primary login
  // must never overwrite another researcher's alias, and an alias must never
  // overwrite another primary or alias.
  const existing = await env.KV.get(allowKey(user), "json");
  if (existing?.alias_of && existing.alias_of !== user) {
    throw new Error("login_in_use_as_alias");
  }
  for (const a of alias) {
    const row = await env.KV.get(allowKey(a), "json");
    if (row && row.login !== user) throw new Error("alias_in_use");
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
  // Re-approval replaces the alias set. Deactivate anything removed from the
  // new entry so an old email cannot remain a second door.
  for (const old of existing?.aliases || []) {
    if (alias.includes(old)) continue;
    const row = await env.KV.get(allowKey(old), "json");
    if (row?.login === user) {
      await env.KV.put(
        allowKey(old),
        JSON.stringify({ ...row, active: false, revoked_at: new Date().toISOString() })
      );
    }
  }
  return entry;
}

export async function revokeResearcher(env, login) {
  const requested = String(login || "").toLowerCase().replace(/^@/, "");
  const requestedEntry = await getAllowEntry(env, requested);
  const user = requestedEntry?.alias_of || requested;
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
