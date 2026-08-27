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

async function strongCall(env, path, body) {
  if (env.CONTROL_PLANE_READY !== "true" || !env.DISCOVERY_CONTROL) return null;
  const stub = env.DISCOVERY_CONTROL.get(env.DISCOVERY_CONTROL.idFromName("global"));
  const response = await stub.fetch(`https://control.internal${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let payload;
  try { payload = await response.json(); } catch { payload = { error: "invalid_control_response" }; }
  return { status: response.status, body: payload };
}

async function matchKvEntry(env, candidates) {
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

export async function isAllowed(env, login) {
  return !!(await matchAllowEntry(env, [login]));
}

/**
 * Find the entry matching any of the identities an assertion presented.
 * Returns the entry and the name that matched, so callers can say which one.
 */
export async function matchAllowEntry(env, candidates) {
  if (!Array.isArray(candidates)) return null;
  const strong = await strongCall(env, "/research/match", { candidates });
  if (strong) {
    if (strong.status !== 200 || strong.body.ok !== true) return null;
    if (strong.body.found) return { entry: strong.body.entry, matched: strong.body.matched };

    // One-time, fail-closed migration of an existing KV approval. A prior DO
    // revocation is a tombstone and refuses to be overwritten by this path.
    const legacy = await matchKvEntry(env, candidates);
    if (!legacy) return null;
    const promoted = await strongCall(env, "/research/approve", {
      entry: legacy.entry,
      migration: true,
    });
    if (!promoted || promoted.status !== 200 || promoted.body.active !== true) return null;
    const verified = await strongCall(env, "/research/match", { candidates });
    return verified?.status === 200 && verified.body.found
      ? { entry: verified.body.entry, matched: verified.body.matched }
      : null;
  }
  return matchKvEntry(env, candidates);
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
  const strong = await strongCall(env, "/research/approve", { entry });
  if (strong && (strong.status !== 200 || strong.body.active !== true)) {
    throw new Error(strong.body.error || "strong_allowlist_activation_failed");
  }
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
  const strong = await strongCall(env, "/research/revoke", { login: user });
  if (strong && (strong.status !== 200 || strong.body.active !== false)) {
    throw new Error(strong.body.error || "strong_allowlist_revocation_failed");
  }
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
