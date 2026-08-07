/** Researcher allowlist keyed by GitHub login (from approved issues). */

export function allowKey(login) {
  return `allowlist:github:${String(login || "").toLowerCase()}`;
}

export async function isAllowed(env, login) {
  if (!login || !env.KV) return false;
  const row = await env.KV.get(allowKey(login), "json");
  return !!(row && row.active !== false);
}

export async function getAllowEntry(env, login) {
  if (!login || !env.KV) return null;
  return env.KV.get(allowKey(login), "json");
}

export async function approveResearcher(env, { login, issue, approved_by, meta }) {
  const user = String(login || "").toLowerCase().replace(/^@/, "");
  if (!/^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$/i.test(user)) {
    throw new Error("invalid_github_login");
  }
  const entry = {
    login: user,
    active: true,
    issue_number: issue || null,
    approved_by: approved_by || null,
    approved_at: new Date().toISOString(),
    meta: meta || null,
  };
  await env.KV.put(allowKey(user), JSON.stringify(entry));
  return entry;
}

export async function revokeResearcher(env, login) {
  const user = String(login || "").toLowerCase().replace(/^@/, "");
  const existing = await getAllowEntry(env, user);
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
