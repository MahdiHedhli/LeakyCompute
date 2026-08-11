/**
 * Shared bits for the suites added alongside spec 001. Kept separate from the
 * original suites so extending coverage never means editing an assertion that
 * already passes.
 */

let failures = 0;

export function section(title) {
  console.log(`\n${title}`);
}

export async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

export function finish() {
  console.log(failures ? `\n${failures} FAILURE(S)` : "\nall assertions passed");
  process.exit(failures ? 1 : 0);
}

/**
 * In-memory KV stub.
 *
 * `deletable: false` models a binding without delete (the shape the original
 * worker.test.mjs stub has). I-26 turns on deletion actually happening, so a
 * suite has to be able to take it away and assert we fail loudly rather than
 * report a sweep that removed nothing.
 */
export function makeKV({ deletable = true } = {}) {
  const store = new Map();
  const ttl = new Map();
  const kv = {
    _store: store,
    _ttl: ttl,
    async get(k, type) {
      const v = store.get(k);
      if (v === undefined) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(k, v, opts) {
      store.set(k, v);
      if (opts && opts.expirationTtl != null) ttl.set(k, opts.expirationTtl);
    },
  };
  if (deletable) {
    kv.delete = async (k) => {
      store.delete(k);
      ttl.delete(k);
    };
  }
  return kv;
}

export const DAY_MS = 86400000;

/** ISO timestamp `days` in the past. */
export function daysAgo(days, now = Date.now()) {
  return new Date(now - days * DAY_MS).toISOString();
}

/** Write a host record straight into KV, bypassing recordExposedHost. */
export async function seedRecord(kv, rec) {
  await kv.put(`discovery:hit:${rec.ip}`, JSON.stringify(rec));
  const index = (await kv.get("discovery:hits_index", "json")) || [];
  if (!index.includes(rec.ip)) index.push(rec.ip);
  await kv.put("discovery:hits_index", JSON.stringify(index));
}

export async function readRecord(kv, ip) {
  return kv.get(`discovery:hit:${ip}`, "json");
}

export function hitKeys(kv) {
  return [...kv._store.keys()].filter((k) => k.startsWith("discovery:hit:"));
}
