/**
 * Private discovery hit store + catalog merge + country aggregates.
 * Raw IPs never leave via public endpoints — admin token only (I-14).
 * Country/ASN/stack counts are safe for public stats.
 *
 * Records are minimised and expire on silence (I-26): see RETAINED_FIELDS.
 */

import { isExcluded, loadExclusions } from "./exclusions.js";

const HITS_INDEX = "discovery:hits_index";
const HIT_PREFIX = "discovery:hit:";
const GEO_KEY = "stats:by_country";
const ASN_KEY = "stats:by_asn";
const STACK_KEY = "stats:by_stack";
// Country x stack, keyed "DE|ollama". Separate by-country and by-stack maps
// cannot answer "what is exposed in Germany" — the cross-tab is the only way,
// and it is still an aggregate, so it stays publishable under I-14.
const COUNTRY_STACK_KEY = "stats:by_country_stack";
const CORPUS_KEY = "stats:corpus";
const ATTEMPTS_KEY = "discovery:probe_attempts";
const SWEEP_STATE_KEY = "discovery:sweep_cursor";
const RECONCILE_STATE_KEY = "discovery:reconcile_state";
// Must cover at least a full I-24 interval at the maximum historical schedule
// volume (2 x 445 x 14 = 12,460). Falling below that silently evicts a recent
// probe clock and makes the host eligible again before 14 days.
const MAX_INDEX = 20000;

/** I-26: 180 days from the last *successful* probe, never from creation. */
export const RETENTION_DAYS = 180;
const DAY_MS = 86400000;

/**
 * The KV TTL is a backstop for the sweep, so it has to fire *after* it, not
 * with it. Computed from the same instant and the same number of days, the TTL
 * always won: the sweep then found the key already gone, took the orphan
 * branch, and pruned the index without ever decrementing the country/ASN/stack
 * aggregates or the re-verified count. The published totals grew monotonically
 * while the note under them claimed "currently retained".
 */
const TTL_GRACE_DAYS = 7;

/**
 * I-24 ledger: when we last *sent* a host a request, whether or not it
 * answered. A host that has gone quiet leaves no exposure record (I-26), so
 * without this the runner sees no last_seen, calls it due, and re-probes it on
 * every run — forever, against exactly the operators who already closed the
 * port. Timestamps only, keyed by address, admin-gated like the hit store
 * (I-14); it carries no observation about the host, only about our own traffic.
 */
const ATTEMPT_RETENTION_DAYS = 90;

/** Per-invocation KV budget for the sweep — see sweepExpiredHosts. */
const SWEEP_MAX_SCAN = 300;
const SWEEP_MAX_DELETE = 30;
// The cron runs this after a sweep. A worst-case sweep can spend several KV
// operations per deletion while it repairs every derived counter, so leave a
// conservative margin beneath Workers' per-invocation KV operation ceiling.
const RECONCILE_MAX_SCAN = 200;
// The admin-only route does not share an invocation with the sweep and can use
// more of the ceiling. Keep room for the index/state reads and final writes.
export const RECONCILE_ADMIN_MAX_SCAN = 800;

/**
 * I-26: the complete list of what a host record may contain. Anything a probe
 * or an index record hands us that is not named here is dropped at write time
 * rather than filtered at read time — model lists, job records, page bodies and
 * free-text org/city strings are content we have no need to keep in order to
 * tell an operator that a port answers unauthenticated reads (I-3).
 */
export const RETAINED_FIELDS = Object.freeze([
  "ip",
  "port",
  "ports",
  "stack",
  "stacks",
  "version",
  "first_seen",
  "last_seen",
  "source",
  "country",
  "country_code",
  "asn",
  // Bookkeeping about our own published counters, not an observation about the
  // host: which country/ASN/stack bucket this record has already been counted
  // into, and whether it is in the re-verified total. It holds no value that is
  // not already retained above. It exists so a decrement lands on the bucket
  // the increment hit — enrichment used to move a record from ZZ to DE without
  // re-keying, so deleting it stole a live host's DE count (see forgetRecord).
  "counted",
]);

/** Pull a version out of an index banner ("Ollama 0.1.40"). */
export function versionFromProduct(product) {
  const m = /(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]+)?)/.exec(String(product || ""));
  return m ? m[1] : null;
}

export async function recordExposedHost(env, hit, batch = null) {
  if (!env.KV || !hit?.ip) return;
  const ip = hit.ip;
  const key = `${HIT_PREFIX}${ip}`;
  const now = new Date().toISOString();
  const prev = (await env.KV.get(key, "json")) || {};
  // A single host can expose more than one stack (e.g. Ollama + Jupyter), so
  // ports/stacks accumulate as sets while port/stack stay for older readers.
  const mergedPorts = uniq([
    ...(prev.ports || (prev.port ? [prev.port] : [])),
    ...(hit.ports || (hit.port ? [hit.port] : [])),
  ]);
  const mergedStacks = uniq([
    ...(prev.stacks || (prev.stack ? [prev.stack] : [])),
    ...(hit.stacks || (hit.stack ? [hit.stack] : [])),
  ]);
  // I-26: only contact resets the clock. A host counted from a public index but
  // never probed (I-22a) must not look "seen today" to the expiry sweep, so
  // callers that merely observed a listing pass `answered: false`.
  const answered = hit.answered !== false;
  const entry = {
    ip,
    port: hit.port || prev.port || 11434,
    ports: mergedPorts,
    stack: hit.stack || prev.stack || null,
    stacks: mergedStacks,
    // The index banner is the only version source for a host we have not
    // fingerprinted ourselves. Reading `version` alone left every
    // discovery-ingested record at null, which silently disabled the whole
    // tier-2 OSV path downstream (no version -> no advisory lookup).
    version: hit.version || versionFromProduct(hit.product) || prev.version || null,
    first_seen: prev.first_seen || now,
    // last_seen IS the last successful probe: this store is only written for a
    // host that answered, and `answered: false` leaves the previous value.
    last_seen: answered ? now : prev.last_seen || null,
    // Kept because I-22 requires every target to trace back to an index record
    // or an approved request; without provenance that check cannot be made.
    source: hit.source || prev.source || "check",
    country: hit.country || prev.country || null,
    country_code: hit.country_code || prev.country_code || null,
    asn: hit.asn || prev.asn || null,
  };

  // --- public aggregates ---------------------------------------------------
  // Every counter this block touches is what /v1/stats publishes, so each bump
  // is recorded on the record itself. Deriving the bucket at delete time from
  // whatever the record ended up holding was the bug: a host first counted
  // under "ZZ" by a self-check, later enriched to "DE" by a discovery ingest,
  // decremented "DE" on expiry and left "ZZ" stranded — the published country
  // chart drifted away from the corpus one host at a time.
  const counted = { ...(prev.counted || {}) };
  const geoBucket = entry.country_code || entry.country || "ZZ";
  const asnBucket = entry.asn || null;

  // A listing we merely counted is not a re-verification (spec §4), and it must
  // not enter the country/ASN totals either: the note under that chart says
  // "re-verified in the last 180 days", so counting an unprobed listing there
  // would make the published figure mean something other than what it claims.
  if (answered) {
    if (counted.geo !== geoBucket) {
      if (counted.geo) await bumpCounter(env, GEO_KEY, counted.geo, -1, batch);
      await bumpCounter(env, GEO_KEY, geoBucket, 1, batch);
      counted.geo = geoBucket;
    }
    if (counted.asn !== asnBucket) {
      if (counted.asn) await bumpCounter(env, ASN_KEY, counted.asn, -1, batch);
      if (asnBucket) await bumpCounter(env, ASN_KEY, asnBucket, 1, batch);
      counted.asn = asnBucket;
    }
    // by_stack counts host+stack pairs: a host first seen with Ollama that
    // later also exposes Jupyter should add to the Jupyter bucket, not be
    // skipped.
    const countedStacks = new Set(counted.stacks || []);
    for (const s of mergedStacks) {
      if (!countedStacks.has(s)) {
        await bumpCounter(env, STACK_KEY, s, 1, batch);
        countedStacks.add(s);
      }
    }
    counted.stacks = [...countedStacks];

    // Cross-tab maintained against the same markers as the two flat maps, so a
    // host that moves country or gains a stack updates all three consistently
    // rather than drifting apart over successive re-probes.
    const prevPairs = new Set(counted.country_stacks || []);
    const nextPairs = new Set(
      [...countedStacks].map((st) => `${geoBucket}|${st}`)
    );
    for (const pair of prevPairs) {
      if (!nextPairs.has(pair)) await bumpCounter(env, COUNTRY_STACK_KEY, pair, -1, batch);
    }
    for (const pair of nextPairs) {
      if (!prevPairs.has(pair)) await bumpCounter(env, COUNTRY_STACK_KEY, pair, 1, batch);
    }
    counted.country_stacks = [...nextPairs];
    // Keyed off the record's own marker rather than off "is this the first
    // write". stats:corpus is newer than the corpus it counts, so gating on
    // first_seen left every pre-existing host permanently uncounted while
    // forgetRecord still decremented for it — the headline re-verified number
    // sat at 0 no matter how many hosts answered. Marking on contact heals a
    // legacy row the next time it is probed.
    if (!counted.reverified) {
      await bumpCorpus(env, "reverified_hosts", 1, now, batch);
      counted.reverified = true;
    }
  }
  entry.counted = counted;

  // TTL backstop for I-26: if the sweep never runs (no cron, failed deploy) the
  // record still ages out of KV on its own, and every answering probe rewrites
  // the key and so restarts the clock. The grace period keeps the sweep ahead
  // of it so the aggregates above are decremented by a real deletion rather
  // than silently orphaned by an expiry we never see.
  await env.KV.put(key, JSON.stringify(entry), {
    expirationTtl: (RETENTION_DAYS + TTL_GRACE_DAYS) * 86400,
  });

  // Staged when batching: this rewrote the entire index array once per host,
  // which is the single largest contributor to the write count on a bulk run.
  if (batch) {
    batch.indexAdds.push(ip);
    return;
  }

  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];
  if (!index.includes(ip)) {
    index.push(ip);
    if (index.length > MAX_INDEX) index = index.slice(-MAX_INDEX);
    await env.KV.put(HITS_INDEX, JSON.stringify(index));
  }
}

/**
 * I-26 sweep: delete every record whose last successful probe is older than the
 * retention window. On-demand so it can be driven from a cron trigger or an
 * admin route without this module owning a schedule.
 *
 * Bounded per invocation, and resumable. Every record read and every counter
 * bump is a KV operation, and KV operations count against the Worker's
 * per-invocation KV-operation ceiling.
 * An unbounded loop over a few hundred hosts trips that ceiling mid-way, and
 * the throw escapes into ctx.waitUntil with no handler — deletions already
 * made, index never rewritten, dangling entries left behind. So the sweep
 * takes a window at a time, records where it stopped, and reports whether more
 * is due; the daily cron walks the corpus over successive runs. A partial
 * sweep is a slower I-26, not a broken one, but a sweep that throws every night
 * is no I-26 at all.
 */
export async function sweepExpiredHosts(
  env,
  {
    now = Date.now(),
    retentionDays = RETENTION_DAYS,
    maxScan = SWEEP_MAX_SCAN,
    maxDelete = SWEEP_MAX_DELETE,
  } = {}
) {
  const summary = {
    scanned: 0,
    deleted: 0,
    retained: 0,
    orphaned: 0,
    cutoff: null,
    remaining: 0,
    complete: true,
  };
  if (!env.KV) return summary;
  // A store we cannot delete from cannot be swept; reporting "0 deleted" would
  // read as "nothing was due", which is the wrong answer to give about I-26.
  if (typeof env.KV.delete !== "function") {
    throw new Error("kv_delete_unavailable");
  }
  const cutoff = now - retentionDays * DAY_MS;
  summary.cutoff = new Date(cutoff).toISOString();
  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];
  if (!index.length) {
    await env.KV.put(SWEEP_STATE_KEY, JSON.stringify({ cursor: null }));
    return summary;
  }

  // Resume where the last window stopped. The cursor is an address rather than
  // an offset because the index shifts under us as hosts are added and removed;
  // an address that has since gone simply restarts the walk.
  const state = (await env.KV.get(SWEEP_STATE_KEY, "json")) || {};
  const resumeAt = state.cursor ? index.indexOf(state.cursor) : -1;
  const start = resumeAt >= 0 ? resumeAt : 0;

  const kept = [];
  let i = start;
  try {
    for (; i < index.length; i++) {
      if (summary.scanned >= maxScan || summary.deleted >= maxDelete) break;
      const ip = index[i];
      summary.scanned++;
      const rec = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
      if (!rec) {
        // Already gone (TTL backstop fired late, or an exclusion deleted it):
        // drop the dangling index entry so listHits and the next sweep stay
        // honest. With TTL_GRACE_DAYS this is the exception, not the rule.
        summary.orphaned++;
        continue;
      }
      // first_seen is a fallback for records that have no contact timestamp at
      // all — legacy writes, or a host only ever counted in an index. It is not
      // a second expiry rule: where contact exists, contact decides (I-26).
      const lastContact = Date.parse(rec.last_seen || rec.first_seen || "");
      if (Number.isFinite(lastContact) && lastContact > cutoff) {
        kept.push(ip);
        summary.retained++;
        continue;
      }
      await forgetRecord(env, rec, ip);
      summary.deleted++;
    }
  } finally {
    // Whatever happened — budget exhausted, KV error mid-loop — the index has
    // to agree with the keys that actually exist before we leave. Rebuilding it
    // only after a clean loop is how a failed sweep left records deleted but
    // still listed.
    const next = [...index.slice(0, start), ...kept, ...index.slice(i)];
    if (next.length !== index.length) await env.KV.put(HITS_INDEX, JSON.stringify(next));
    // Resume from the first entry this window did not reach — by address, so a
    // throw partway through resumes there too instead of re-walking the corpus.
    const completed = i >= index.length;
    const cursor = completed ? null : index[i] || null;
    await env.KV.put(SWEEP_STATE_KEY, JSON.stringify({ cursor, at: new Date(now).toISOString() }));
    summary.remaining = completed ? 0 : index.length - i;
    summary.complete = completed;
  }
  return summary;
}

/**
 * I-24 probe ledger: record that we sent these addresses a request.
 *
 * The exposure store cannot serve as the re-probe clock, because it only ever
 * holds hosts that answered. A host that has been firewalled since a public
 * index listed it leaves no record at all, so the runner sees no last_seen,
 * classes it as due, and probes it again on the next run — daily, indefinitely,
 * against an operator who has already done the thing we exist to ask for. I-24
 * says "at most one probe cycle per host per 14 days" without qualification, so
 * the clock has to cover attempts, not outcomes.
 *
 * One KV key holding timestamps only. Entries older than the window are dropped
 * on write, so this never becomes a second, quieter corpus of hosts we have no
 * finding about (I-26).
 */
export async function recordProbeAttempts(env, ips, { now = Date.now() } = {}) {
  if (!env.KV || !Array.isArray(ips) || !ips.length) return { tracked: 0 };
  const at = new Date(now).toISOString();
  const map = (await env.KV.get(ATTEMPTS_KEY, "json")) || {};
  const floor = now - ATTEMPT_RETENTION_DAYS * DAY_MS;
  const next = {};
  for (const [ip, ts] of Object.entries(map)) {
    const t = Date.parse(ts);
    if (Number.isFinite(t) && t > floor) next[ip] = ts;
  }
  for (const ip of ips) {
    if (ip) next[ip] = at;
  }
  // Newest wins if the ledger is somehow over the bound: the oldest entries are
  // the ones whose interval has nearly elapsed anyway.
  const entries = Object.entries(next).sort((a, b) => String(b[1]).localeCompare(String(a[1])));
  await env.KV.put(ATTEMPTS_KEY, JSON.stringify(Object.fromEntries(entries.slice(0, MAX_INDEX))));
  return { tracked: Math.min(entries.length, MAX_INDEX) };
}

/** The re-probe clock the runner reads before it emits anything (I-24). */
export async function getProbeAttempts(env) {
  if (!env.KV) return {};
  const map = (await env.KV.get(ATTEMPTS_KEY, "json")) || {};
  return map && typeof map === "object" ? map : {};
}

/**
 * Delete records for specific hosts. Exists so an exclusion (I-25) can remove
 * what we already hold, not merely stop future probes.
 */
export async function forgetHosts(env, ips) {
  if (!env.KV || !Array.isArray(ips) || !ips.length) return { deleted: 0 };
  if (typeof env.KV.delete !== "function") throw new Error("kv_delete_unavailable");
  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];
  const targets = new Set(ips.filter(Boolean));
  let deleted = 0;
  for (const ip of targets) {
    const rec = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
    if (!rec) continue;
    await forgetRecord(env, rec, ip);
    deleted++;
  }
  const kept = index.filter((ip) => !targets.has(ip));
  if (kept.length !== index.length) await env.KV.put(HITS_INDEX, JSON.stringify(kept));
  // An operator who asked to be left alone has not asked us to keep a note of
  // when we last contacted them either (I-25).
  await dropProbeAttempts(env, [...targets]);
  return { deleted };
}

async function dropProbeAttempts(env, ips) {
  if (!env.KV || !ips.length) return;
  const map = (await env.KV.get(ATTEMPTS_KEY, "json")) || {};
  let touched = false;
  for (const ip of ips) {
    if (ip in map) {
      delete map[ip];
      touched = true;
    }
  }
  if (touched) await env.KV.put(ATTEMPTS_KEY, JSON.stringify(map));
}

/**
 * I-25: delete every stored record covered by an exclusion list.
 *
 * Takes the *whole* current list, not just the lines a single request added.
 * addExclusions drops entries it already holds, so purging only the newly
 * accepted ones meant a re-filed removal request — the thing an operator does
 * when the first one visibly did not work — purged nothing at all.
 *
 * IP and CIDR rules are matched against the index, which is a list of
 * addresses, so they cost no record reads. Only an ASN rule needs the record
 * itself, and that read budget is bounded and reported: the caller must be able
 * to tell "nothing matched" from "we ran out of budget before we knew".
 */
export async function purgeExcluded(env, entries, { maxReads = 400 } = {}) {
  const out = { deleted: 0, matched: 0, scanned: 0, complete: true };
  if (!env.KV || !Array.isArray(entries) || !entries.length) return out;
  if (typeof env.KV.delete !== "function") {
    return { ...out, error: "kv_delete_unavailable" };
  }
  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];

  const doomed = new Set();
  const byAddress = entries.filter((e) => e?.type !== "asn");
  const byAsn = entries.filter((e) => e?.type === "asn");
  for (const ip of index) {
    if (byAddress.length && isExcluded(byAddress, { ip })) doomed.add(ip);
  }
  if (byAsn.length) {
    for (const ip of index) {
      if (doomed.has(ip)) continue;
      if (out.scanned >= maxReads) {
        out.complete = false;
        break;
      }
      out.scanned++;
      const rec = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
      if (rec && isExcluded(byAsn, { ip, asn: rec.asn })) doomed.add(ip);
    }
  }
  out.matched = doomed.size;
  const { deleted } = await forgetHosts(env, [...doomed]);
  out.deleted = deleted;

  // The probe ledger is keyed independently of the corpus — a host that never
  // answered has an entry here and no record anywhere else — so it needs its
  // own pass or an opt-out would leave the one trace of them we still hold.
  // Address rules only: the ledger stores no ASN to match one against.
  if (byAddress.length) {
    const attempts = await getProbeAttempts(env);
    const stale = Object.keys(attempts).filter((ip) => isExcluded(byAddress, { ip }));
    if (stale.length) {
      await dropProbeAttempts(env, stale);
      out.forgotten_attempts = stale.length;
    }
  }
  return out;
}

async function forgetRecord(env, rec, ip) {
  await env.KV.delete(`${HIT_PREFIX}${ip}`);
  // Aggregates are counts of hosts we currently hold. Leaving a deleted host in
  // the country/ASN/stack totals would keep publishing a host we no longer have
  // evidence for, and would double-count it if it ever answers again.
  //
  // `counted` is the authority on which bucket to give back, because it is the
  // bucket the increment went into. The derivations behind it are the legacy
  // path only — records written before that marker existed — and they are the
  // shape that drifted, so they are a fallback, never the first choice.
  const counted = rec.counted || null;
  const geo = counted ? counted.geo : rec.country_code || rec.country || "ZZ";
  if (geo) await bumpCounter(env, GEO_KEY, geo, -1);
  const asn = counted ? counted.asn : rec.asn;
  if (asn) await bumpCounter(env, ASN_KEY, asn, -1);
  const stacks = counted ? counted.stacks || [] : rec.stacks || (rec.stack ? [rec.stack] : []);
  for (const s of stacks) {
    await bumpCounter(env, STACK_KEY, s, -1);
  }
  for (const pair of counted?.country_stacks || []) {
    await bumpCounter(env, COUNTRY_STACK_KEY, pair, -1);
  }
  // No marker means we have no evidence this record was ever counted in, and
  // the corpus counter is younger than most of the corpus. Decrementing on a
  // guess is how the published re-verified figure ended up drifting toward zero
  // while the hosts were still answering, so absence of proof is treated as
  // not-counted. A legacy record picks up its marker the next time it is
  // probed, and from then on the two sides agree.
  if (counted?.reverified) await bumpCorpus(env, "reverified_hosts", -1);
}

function uniq(list) {
  return [...new Set(list.filter((v) => v != null && v !== ""))];
}

/* ------------------------------------------------------------------ */
/* Write batching                                                      */
/* ------------------------------------------------------------------ */

/**
 * KV write budget is the binding constraint on ingest size, not CPU.
 *
 * Every counter here is a read-modify-write of a whole map, so recording one
 * host touched six keys: the record, the index, three aggregate maps and the
 * corpus totals. A 362-host run therefore issued ~2,100 puts against a free
 * tier of 1,000/day and tripped the limit mid-run — the dangerous failure, since
 * a record can land while the aggregates that describe it do not.
 *
 * A batch accumulates every aggregate mutation in memory and flushes one put per
 * distinct key at the end, which turns those six-per-host into one-per-host plus
 * a fixed five. Passing no batch keeps the immediate behaviour, so the
 * single-host paths (/v1/check) are unchanged.
 */
export function createWriteBatch() {
  return {
    counters: new Map(), // mapKey -> Map(label -> delta)
    corpus: new Map(), // field -> delta
    corpusAt: null,
    indexAdds: [],
    puts: 0,
  };
}

function stageCounter(batch, mapKey, label, delta) {
  if (!batch.counters.has(mapKey)) batch.counters.set(mapKey, new Map());
  const m = batch.counters.get(mapKey);
  m.set(label, (m.get(label) || 0) + delta);
}

export async function flushWriteBatch(env, batch) {
  if (!env.KV || !batch) return { puts: 0 };
  let puts = 0;

  for (const [mapKey, deltas] of batch.counters) {
    const map = (await env.KV.get(mapKey, "json")) || {};
    for (const [label, delta] of deltas) {
      const next = (map[label] || 0) + delta;
      if (next > 0) map[label] = next;
      else delete map[label];
    }
    await env.KV.put(mapKey, JSON.stringify(map));
    puts++;
  }

  if (batch.corpus.size || batch.corpusAt) {
    const corpus = (await env.KV.get(CORPUS_KEY, "json")) || {};
    for (const [field, delta] of batch.corpus) {
      corpus[field] = Math.max(0, (corpus[field] || 0) + delta);
    }
    if (batch.corpusAt) corpus.last_reverified_at = batch.corpusAt;
    await env.KV.put(CORPUS_KEY, JSON.stringify(corpus));
    puts++;
  }

  if (batch.indexAdds.length) {
    let index = (await env.KV.get(HITS_INDEX, "json")) || [];
    if (!Array.isArray(index)) index = [];
    const seen = new Set(index);
    let changed = false;
    for (const ip of batch.indexAdds) {
      if (!seen.has(ip)) {
        index.push(ip);
        seen.add(ip);
        changed = true;
      }
    }
    if (changed) {
      if (index.length > MAX_INDEX) index = index.slice(-MAX_INDEX);
      await env.KV.put(HITS_INDEX, JSON.stringify(index));
      puts++;
    }
  }

  batch.puts += puts;
  return { puts };
}


async function bumpCounter(env, mapKey, label, delta = 1, batch = null) {
  if (!label) return;
  if (batch) return stageCounter(batch, mapKey, label, delta);
  const map = (await env.KV.get(mapKey, "json")) || {};
  const next = (map[label] || 0) + delta;
  if (next > 0) map[label] = next;
  else delete map[label];
  await env.KV.put(mapKey, JSON.stringify(map));
}

async function bumpCorpus(env, field, delta, at = null, batch = null) {
  if (batch) {
    batch.corpus.set(field, (batch.corpus.get(field) || 0) + delta);
    if (at && delta >= 0) batch.corpusAt = at;
    return;
  }
  const corpus = (await env.KV.get(CORPUS_KEY, "json")) || {};
  corpus[field] = Math.max(0, (corpus[field] || 0) + delta);
  // delta 0 is a real case: a host that answers again is already in the count,
  // but it did just re-verify, and last_reverified_at is what says so.
  if (at && delta >= 0) corpus.last_reverified_at = at;
  await env.KV.put(CORPUS_KEY, JSON.stringify(corpus));
}

/**
 * Counts behind the three-number split (spec §4). Hosts only — no identifiers,
 * so this is safe to surface publicly (I-14).
 */
export async function getCorpusCounts(env) {
  const defaults = {
    reverified_hosts: 0,
    indexed_observed_hosts: 0,
    indexed_observed_source: null,
    last_reverified_at: null,
    last_observed_at: null,
  };
  if (!env.KV) return defaults;
  try {
    return { ...defaults, ...((await env.KV.get(CORPUS_KEY, "json")) || {}) };
  } catch {
    return defaults;
  }
}

/**
 * Hosts a public index listed and we counted without probing (I-21, spec §4).
 * This is a *measurement replaced on each run*, not a running total: nothing is
 * stored per host, so there is no record whose deletion could decrement it, and
 * accumulating would inflate it every time the same lane is counted again.
 */
export async function setIndexedObserved(env, count, source = null, sources = null) {
  const n = Number(count);
  if (!env.KV || !Number.isFinite(n) || n < 0) return;
  const corpus = (await env.KV.get(CORPUS_KEY, "json")) || {};
  corpus.indexed_observed_hosts = Math.floor(n);
  corpus.indexed_observed_source = source || corpus.indexed_observed_source || null;
  // Per-source breakdown. The headline is a composite, so every component has
  // to be visible or the total stops being auditable — someone reading "18,686
  // indexed" must be able to see which index said what, and which of it we were
  // asked to look at rather than found listed.
  if (sources && typeof sources === "object") {
    const clean = {};
    for (const [k, v] of Object.entries(sources)) {
      const num = Number(v);
      if (Number.isFinite(num) && num >= 0) clean[k] = Math.floor(num);
    }
    if (Object.keys(clean).length) corpus.indexed_observed_sources = clean;
  }
  corpus.last_observed_at = new Date().toISOString();
  await env.KV.put(CORPUS_KEY, JSON.stringify(corpus));
}

export async function getCountryStackStats(env) {
  if (!env.KV) return {};
  return (await env.KV.get(COUNTRY_STACK_KEY, "json")) || {};
}

export async function getGeoStats(env) {
  if (!env.KV) {
    return { by_country: [], by_asn: [], by_stack: [] };
  }
  const countries = (await env.KV.get(GEO_KEY, "json")) || {};
  const asns = (await env.KV.get(ASN_KEY, "json")) || {};
  const stacks = (await env.KV.get(STACK_KEY, "json")) || {};
  const toSorted = (obj, keyName) =>
    Object.entries(obj)
      .map(([k, count]) => ({ [keyName]: k, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 50);
  return {
    by_country: toSorted(countries, "country"),
    by_asn: toSorted(asns, "asn"),
    by_stack: toSorted(stacks, "stack"),
  };
}

export async function listHits(env, { limit = 500, sort = "last_seen" } = {}) {
  if (!env.KV) return [];
  const index = (await env.KV.get(HITS_INDEX, "json")) || [];
  const ips = (Array.isArray(index) ? index : []).slice(-Math.min(limit, MAX_INDEX));

  // Read in parallel chunks. One await per record is ~140ms of KV latency each,
  // so 343 records took 47 seconds and the runner's fetch timed out — which
  // took the corpus out as a candidate source entirely. Chunked so a large
  // corpus does not open hundreds of concurrent subrequests at once.
  const CHUNK = 40;
  const out = [];
  for (let i = 0; i < ips.length; i += CHUNK) {
    const rows = await Promise.all(
      ips.slice(i, i + CHUNK).map((ip) => env.KV.get(`${HIT_PREFIX}${ip}`, "json"))
    );
    for (const row of rows) if (row) out.push(row);
  }
  if (sort === "country") {
    out.sort((a, b) =>
      String(a.country_code || a.country || "ZZ").localeCompare(
        String(b.country_code || b.country || "ZZ")
      )
    );
  } else if (sort === "asn") {
    out.sort((a, b) => String(a.asn || "").localeCompare(String(b.asn || "")));
  } else {
    out.sort((a, b) => String(b.last_seen || "").localeCompare(String(a.last_seen || "")));
  }
  return out;
}

export async function mergeValidatedModels(env, modelHits) {
  if (!env.KV || !Array.isArray(modelHits)) return;
  const catalog = (await env.KV.get("catalog:validated", "json")) || {
    models: [],
    updated_at: null,
  };
  const byName = Object.create(null);
  for (const m of catalog.models || []) byName[m.model] = m;
  for (const hit of modelHits) {
    const name = hit.model;
    if (!name) continue;
    const prev = byName[name] || {
      model: name,
      hosts: 0,
      size: hit.size || "?",
      validated: true,
      source: hit.source || "discovery",
    };
    prev.hosts = Math.max(prev.hosts || 0, hit.hosts || 1);
    prev.validated = true;
    prev.last_validated = new Date().toISOString();
    prev.source = hit.source || prev.source;
    byName[name] = prev;
  }
  catalog.models = Object.values(byName)
    .sort((a, b) => (b.hosts || 0) - (a.hosts || 0))
    .slice(0, 2500);
  catalog.updated_at = new Date().toISOString();
  await env.KV.put("catalog:validated", JSON.stringify(catalog));
  return catalog;
}

/* ------------------------------------------------------------------ */
/* Daily KV write budget                                               */
/* ------------------------------------------------------------------ */

/**
 * Workers KV free tier allows 1,000 put operations a day, and exceeding it
 * blocks writes account-wide until 00:00 UTC. The dangerous part is not the
 * block, it is *where* it lands: a record can be written while the aggregates
 * describing it are not, leaving published counts that disagree with the corpus.
 *
 * So the ceiling is checked before a batch starts rather than discovered
 * halfway through. The default sits under the free-tier limit; a paid account
 * raises it with KV_DAILY_PUT_BUDGET.
 */
export const DEFAULT_KV_DAILY_PUTS = 900;

function budgetKey(now = Date.now()) {
  return `kv:puts:${new Date(now).toISOString().slice(0, 10)}`;
}

export function kvBudget(env) {
  const n = Number(env?.KV_DAILY_PUT_BUDGET);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_KV_DAILY_PUTS;
}

/** Would this batch cross the ceiling? Checked before any write. */
export async function checkWriteBudget(env, estimatedPuts) {
  if (!env.KV) return { ok: true, used: 0, budget: 0, remaining: 0 };
  const budget = kvBudget(env);
  const used = Number(await env.KV.get(budgetKey(), "text")) || 0;
  const remaining = Math.max(0, budget - used);
  return {
    ok: estimatedPuts <= remaining,
    used,
    budget,
    remaining,
    estimated: estimatedPuts,
  };
}

async function chargeWriteBudget(env, puts) {
  if (!env.KV) return { used: 0, budget: 0 };
  const budget = kvBudget(env);
  const key = budgetKey();
  const used = (Number(await env.KV.get(key, "text")) || 0) + puts;
  // +1 for this write itself. Counted, because a budget that does not count its
  // own bookkeeping drifts under the real ceiling exactly when it matters.
  await env.KV.put(key, String(used + 1), { expirationTtl: 3 * 86400 });
  return { used: used + 1, budget };
}

/* ------------------------------------------------------------------ */
/* Known-CVE summary (secondary to exposure classes)                   */
/* ------------------------------------------------------------------ */

const VULN_SUMMARY_KEY = "stats:vuln_summary";

export async function getVulnSummary(env) {
  if (!env.KV) return null;
  return (await env.KV.get(VULN_SUMMARY_KEY, "json")) || null;
}

/**
 * Aggregate known CVEs across the hosts that disclose a version.
 *
 * Deliberately a *secondary* figure. Only about one host in eight publishes a
 * version string, so this can never describe the corpus the way the exposure
 * classes do — and a CVE count that silently covered an eighth of the hosts
 * while looking like it covered all of them is the failure this project exists
 * to avoid. The denominator travels with the number for that reason.
 *
 * Counts hosts running a version with a published advisory. It does not mean
 * exploitable: we never test, and several of these services are unauthenticated
 * by design, where no upgrade changes anything (I-3).
 *
 * Queried per distinct (stack, version), not per host, and OSV responses are
 * KV-cached, so a run costs a handful of lookups rather than one per record.
 */
export async function summariseVulns(env, results, { queryOsv, packages } = {}) {
  if (!env.KV || !queryOsv || !packages) return null;

  const pairs = new Map(); // "stack|version" -> host count
  let withVersion = 0;
  for (const r of results || []) {
    if (!r?.exposed || !r.version || !r.stack) continue;
    withVersion++;
    const key = `${r.stack}|${r.version}`;
    pairs.set(key, (pairs.get(key) || 0) + 1);
  }
  if (!pairs.size) return null;

  const byCve = new Map();
  let hostsWithCve = 0;
  let pairsChecked = 0;

  for (const [key, hosts] of pairs) {
    const [stack, version] = key.split("|");
    const pkg = packages[stack];
    if (!pkg) continue; // OSV covers a subset of the stacks we probe
    pairsChecked++;
    let vulns = [];
    try {
      vulns = await queryOsv(pkg, version, env);
    } catch {
      continue; // never fail an ingest over an enrichment lookup
    }
    if (!Array.isArray(vulns) || !vulns.length) continue;
    hostsWithCve += hosts;
    for (const v of vulns) {
      const id = v?.id || v?.aliases?.[0];
      if (!id) continue;
      byCve.set(id, (byCve.get(id) || 0) + hosts);
    }
  }

  const summary = {
    hosts_with_version: withVersion,
    hosts_with_known_cve: hostsWithCve,
    version_pairs_checked: pairsChecked,
    top_cves: [...byCve.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([id, hosts]) => ({ id, hosts })),
    updated_at: new Date().toISOString(),
    note:
      "Counted only across hosts that disclose a version, and only for stacks " +
      "OSV indexes. Running an affected version is not the same as being " +
      "exploitable — we report reachability, never demonstrated impact.",
  };
  await env.KV.put(VULN_SUMMARY_KEY, JSON.stringify(summary));
  return summary;
}

export async function ingestDiscoveryBatch(env, batch) {
  /**
   * results: [{ ip, port, exposed, version, models, source, stack, country, country_code, asn, ... }]
   *
   * A batch may carry more than the record schema allows. I-26 is enforced here
   * by what we pass on, not by what the runner sends: model names survive only
   * as anonymous counts in the validated catalog (no host attached), and job
   * records, page bodies, city, org and per-host vuln lists are dropped.
   */
  const all = batch.results || [];
  // I-25 is enforced in the runner before a packet is emitted, but the runner
  // may be holding a list that predates a removal filed mid-run. Re-checking
  // here is what stops an ingest from writing an excluded operator straight
  // back into the corpus a purge just cleared.
  // The stored list is authoritative and must be readable. A caller-provided
  // snapshot can add exclusions, never replace or weaken the current list.
  const authoritativeExclusions = await loadExclusions(env);
  const suppliedExclusions = Array.isArray(batch.exclusions) ? batch.exclusions : [];
  const exclusions = [...authoritativeExclusions, ...suppliedExclusions];
  const results = [];
  let refused = 0;
  for (const r of all) {
    if (r?.ip && isExcluded(exclusions, { ip: r.ip, asn: r.asn })) refused++;
    else results.push(r);
  }

  // I-24: the ledger of what we contacted, answered or not. Written for every
  // result in the batch, because the hosts that most need the interval honoured
  // are the ones that no longer answer and so leave no record below.
  await recordProbeAttempts(
    env,
    results.map((r) => r?.ip).filter(Boolean)
  );

  // One write batch for the whole ingest: aggregate mutations accumulate in
  // memory and flush as a fixed handful of puts instead of six per host.
  // Named `writes` because `batch` is already this function's payload.
  const writes = createWriteBatch();

  let exposed = 0;
  const modelHits = [];
  for (const r of results) {
    if (!r || !r.ip) continue;
    if (r.exposed) {
      exposed++;
      const models = (r.models || []).map((m) => ({
        name: m.name || m.model,
        size: m.size || null,
      }));
      await recordExposedHost(env, {
        ip: r.ip,
        port: r.port || 11434,
        ports: r.ports || null,
        source: r.source || "discovery",
        stack: r.stack || null,
        stacks: r.stacks || null,
        version: r.version || null,
        // Not retained: the banner is read for its version substring and
        // dropped (I-26). Without it every discovery-ingested record stored
        // version: null, and a null version means no OSV lookup downstream.
        product: r.product || null,
        country: r.country || null,
        country_code: r.country_code || null,
        asn: r.asn || null,
        answered: r.answered !== false,
      }, writes);
      for (const m of models) {
        if (m.name) {
          modelHits.push({
            model: m.name,
            hosts: 1,
            size: m.size,
            source: r.source || "discovery",
          });
        }
      }
    }
  }
  if (modelHits.length) await mergeValidatedModels(env, modelHits);
  // Once per batch rather than once per host: a re-probe of an already-counted
  // host changes no count, only the "when did we last re-verify anything"
  // stamp, and paying two KV operations per host for that is how a large batch
  // runs out of subrequests.
  if (exposed) await bumpCorpus(env, "reverified_hosts", 0, new Date().toISOString(), writes);

  // Flush the staged aggregates. Must happen before the summary is returned so
  // a caller that trusts the response also gets the counts it describes.
  const flushed = await flushWriteBatch(env, writes);

  const statsKey = "stats:live";
  const stats = (await env.KV.get(statsKey, "json")) || {
    checks_total: 0,
    exposed_total: 0,
    models_top: [],
  };
  stats.checks_total = (stats.checks_total || 0) + results.length;
  stats.exposed_total = (stats.exposed_total || 0) + exposed;
  stats.last_check_at = new Date().toISOString();
  stats.updated_at = stats.last_check_at;
  stats.discovery_runs = (stats.discovery_runs || 0) + 1;
  stats.last_discovery_at = stats.last_check_at;
  if (batch.run_meta) stats.last_discovery_meta = batch.run_meta;
  await env.KV.put(statsKey, JSON.stringify(stats));

  // Passive breadth: how many hosts the index lane listed, whether or not we
  // probed them. Reported on its own line (spec §4) so a larger passive count
  // can never be read as a larger number of hosts we touched.
  const observed = batch.indexed_observed ?? batch.run_meta?.indexed_observed;
  if (observed != null) {
    await setIndexedObserved(
      env,
      observed,
      batch.run_meta?.observed_source || null,
      batch.indexed_observed_sources ?? batch.run_meta?.indexed_observed_sources ?? null
    );
  }

  // Best-effort enrichment: never let a lookup failure cost us the ingest.
  try {
    const { queryOsv, OSV_PACKAGES } = await import("./osv.js");
    await summariseVulns(env, results, { queryOsv, packages: OSV_PACKAGES });
  } catch {
    // leave the previous summary in place rather than blanking it
  }

  const spent = await chargeWriteBudget(env, flushed.puts + results.length);

  return {
    ingested: results.length,
    exposed,
    models_touched: modelHits.length,
    // Reported rather than silently dropped: a runner whose exclusion list is
    // stale needs to find that out, and the count is the only signal it gets.
    refused_excluded: refused,
    // Observability on the constraint that actually binds ingest size. A run
    // that cannot see what it spent cannot be sized against the daily ceiling.
    kv_puts: flushed.puts + results.length,
    kv_puts_today: spent.used,
    kv_budget: spent.budget,
  };
}

/* ------------------------------------------------------------------ */
/* Final re-verification queue + lane cursors                          */
/* ------------------------------------------------------------------ */

/**
 * A record reaching the retention limit gets one last probe before it is
 * deleted, rather than ageing out unobserved.
 *
 * The distinction matters to the research, not just to tidiness: a host that
 * stops answering has either been remediated or has moved, and deleting it on a
 * timer records neither. Probing it on the way out turns an expiry into a
 * measurement — the operator fixed it, or the address went away — and that is
 * the only signal this project has that anything it publishes ever helped.
 *
 * Due one day before the limit so the runner has a full cycle to act. Hosts
 * past the limit are still returned: if the runner was down for a week, the
 * backlog is the queue, not a set of silent deletions.
 */
export const FINAL_VERIFY_DAYS = RETENTION_DAYS - 1;

export async function listExpiringHosts(
  env,
  { now = Date.now(), dueDays = FINAL_VERIFY_DAYS, limit = 500 } = {}
) {
  if (!env.KV) return { due: [], cutoff: null, count: 0 };
  const cutoff = now - dueDays * DAY_MS;
  const index = (await env.KV.get(HITS_INDEX, "json")) || [];
  const due = [];

  for (const ip of Array.isArray(index) ? index : []) {
    if (due.length >= limit) break;
    const rec = await env.KV.get(`${HIT_PREFIX}${ip}`, "json");
    if (!rec) continue;
    const seen = Date.parse(rec.last_seen || rec.first_seen || "");
    if (!Number.isFinite(seen) || seen > cutoff) continue;
    due.push({
      ip: rec.ip,
      port: rec.port,
      // Carried so the runner can rebuild provenance (I-22) and pick a probe
      // path. A row whose source is not a public index will be dropped by the
      // provenance gate, which is correct: a self-check never entitled us to
      // re-probe that host later.
      stack: rec.stack || null,
      source: rec.source || null,
      asn: rec.asn || null,
      last_seen: rec.last_seen || null,
      age_days: Math.floor((now - seen) / DAY_MS),
      final_verification: true,
    });
  }

  due.sort((a, b) => b.age_days - a.age_days);
  return { due, cutoff: new Date(cutoff).toISOString(), count: due.length };
}

/**
 * Delete a host after its final probe found nothing. Distinct from the timer
 * sweep: this is deletion with evidence behind it.
 */
export async function retireUnreachableHost(env, ip, { reason = "final_probe_no_answer" } = {}) {
  // Delegates to forgetHosts rather than calling forgetRecord directly: the
  // record and the aggregates are only half the state, and leaving the address
  // in HITS_INDEX would have the sweep rediscover a key that no longer exists
  // and book it as an orphan every night.
  const res = await forgetHosts(env, [ip]);
  return { ip, deleted: res.deleted > 0, reason: res.deleted ? reason : "not_found" };
}

const CURSOR_KEY = "discovery:lane_cursors";

/**
 * Per-lane Shodan pagination state.
 *
 * shodan_search() opened at page 1 on every invocation, so consecutive runs
 * bought the same first hundred results over and over: the corpus stopped
 * growing while the query credits still drained. Advancing a cursor per lane
 * walks down the result set instead of re-reading the top of it.
 *
 * Wrapping back to page 1 when a lane is exhausted is deliberate — the index
 * changes underneath us, so the top of the list a month later is not the list
 * we already have.
 */
export async function getLaneCursors(env) {
  if (!env.KV) return {};
  return (await env.KV.get(CURSOR_KEY, "json")) || {};
}

export async function setLaneCursor(env, lane, { page, exhausted = false, observed = 0 }) {
  if (!env.KV || !lane) return null;
  const all = (await env.KV.get(CURSOR_KEY, "json")) || {};
  const p = Number(page);
  all[lane] = {
    page: Number.isFinite(p) && p >= 1 ? Math.floor(p) : 1,
    exhausted: !!exhausted,
    observed_last_run: Number(observed) || 0,
    updated_at: new Date().toISOString(),
  };
  await env.KV.put(CURSOR_KEY, JSON.stringify(all));
  return all[lane];
}

/* ------------------------------------------------------------------ */
/* Reconciliation                                                      */
/* ------------------------------------------------------------------ */

/**
 * Recompute the published aggregates from the records themselves.
 *
 * Every counter here is derived: incremented once per record, gated on a marker
 * stored on that record and set in the same breath as the increment. When the
 * two do not land together — a failed batch flush, a blocked KV write — the
 * record keeps the marker and the counter never gets its increment back. The
 * drift is therefore one-directional and permanent: reverified_hosts read 478
 * against 629 actual records, and nothing in the system could notice.
 *
 * A derived number with no path back to its source is a number that will be
 * wrong eventually. This is that path: the index is authoritative, so walk it
 * and rewrite the totals to match.
 *
 * Bounded per invocation for the same reason the sweep is. Staging counters and
 * the exact index snapshot are checkpointed in private KV; live aggregates are
 * switched only after every record in that snapshot has been processed.
 */
export async function reconcileCorpusCounts(env, { limit = RECONCILE_MAX_SCAN } = {}) {
  if (!env.KV) return { ok: false, reason: "no_kv" };

  let index = (await env.KV.get(HITS_INDEX, "json")) || [];
  if (!Array.isArray(index)) index = [];
  const scanLimit = Math.max(
    1,
    Math.min(Number(limit) || RECONCILE_MAX_SCAN, RECONCILE_ADMIN_MAX_SCAN)
  );

  let state = await env.KV.get(RECONCILE_STATE_KEY, "json");
  const sameSnapshot =
    state?.version === 1 &&
    Array.isArray(state.ips) &&
    state.ips.length === index.length &&
    state.ips.every((ip, i) => ip === index[i]);

  // Counts from two different index versions must never be combined. If a
  // retention sweep or admin ingest changed the authoritative list between
  // chunks, discard the accumulator and start a fresh snapshot.
  if (!sameSnapshot) {
    state = {
      version: 1,
      ips: [...index],
      cursor: 0,
      geo: {},
      asn: {},
      stack: {},
      country_stack: {},
      records: 0,
      orphaned_index_entries: 0,
      started_at: new Date().toISOString(),
    };
  }

  const start = Math.max(0, Math.min(Number(state.cursor) || 0, state.ips.length));
  const ips = state.ips.slice(start, start + scanLimit);

  const CHUNK = 40;
  for (let i = 0; i < ips.length; i += CHUNK) {
    const rows = await Promise.all(
      ips.slice(i, i + CHUNK).map((ip) => env.KV.get(`${HIT_PREFIX}${ip}`, "json"))
    );
    for (const rec of rows) {
      if (!rec) {
        state.orphaned_index_entries++;
        continue;
      }
      state.records++;
      const g = rec.country_code || rec.country || "ZZ";
      state.geo[g] = (state.geo[g] || 0) + 1;
      if (rec.asn) state.asn[rec.asn] = (state.asn[rec.asn] || 0) + 1;
      const stacks = rec.stacks?.length ? rec.stacks : rec.stack ? [rec.stack] : [];
      for (const s of stacks) {
        state.stack[s] = (state.stack[s] || 0) + 1;
        const pair = `${g}|${s}`;
        state.country_stack[pair] = (state.country_stack[pair] || 0) + 1;
      }
    }
  }

  state.cursor = start + ips.length;
  state.updated_at = new Date().toISOString();
  const complete = state.cursor >= state.ips.length;

  if (!complete) {
    await env.KV.put(RECONCILE_STATE_KEY, JSON.stringify(state));
    return {
      ok: true,
      records: state.records,
      orphaned_index_entries: state.orphaned_index_entries,
      scanned: ips.length,
      scanned_total: state.cursor,
      total: state.ips.length,
      remaining: state.ips.length - state.cursor,
      complete: false,
      started_at: state.started_at,
    };
  }

  const corpus = (await env.KV.get(CORPUS_KEY, "json")) || {};
  const before = corpus.reverified_hosts || 0;
  corpus.reverified_hosts = state.records;
  corpus.reconciled_at = new Date().toISOString();

  await env.KV.put(CORPUS_KEY, JSON.stringify(corpus));
  await env.KV.put(GEO_KEY, JSON.stringify(state.geo));
  await env.KV.put(ASN_KEY, JSON.stringify(state.asn));
  await env.KV.put(STACK_KEY, JSON.stringify(state.stack));
  await env.KV.put(COUNTRY_STACK_KEY, JSON.stringify(state.country_stack));
  if (typeof env.KV.delete === "function") await env.KV.delete(RECONCILE_STATE_KEY);

  return {
    ok: true,
    records: state.records,
    reverified_before: before,
    reverified_after: state.records,
    drift: state.records - before,
    orphaned_index_entries: state.orphaned_index_entries,
    scanned: ips.length,
    scanned_total: state.cursor,
    total: state.ips.length,
    remaining: 0,
    complete: true,
    started_at: state.started_at,
  };
}
