/**
 * Lab render primitives.
 *
 * I-16: every string the lab renders may have been produced by a probed host —
 * version banners, product strings, org/city names, OSV titles, source labels.
 * A hostile operator who wants to be un-studied only has to set a version
 * string to a <script> tag, so the rule enforced here is that escaping is the
 * default and bypassing it is explicit and greppable:
 *
 *   - `h` escapes EVERY interpolated value, including inside attributes.
 *   - the only way to inject markup is `raw()`, and the only callers of `raw()`
 *     are `h` itself (so nested templates compose) and this file's own
 *     numeric/static builders. No probed string is ever passed to `raw()`.
 *   - `render(el, node)` refuses to put a bare string into innerHTML unescaped.
 *
 * `esc()` is deliberately identical to the one in public/js/app.js rather than
 * cleverer: two escapers that disagree is how one of them ends up wrong.
 */

const RAW = Symbol("lab.raw");

export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[c]);
}

/** Mark a string as already-safe markup. Grep this symbol to audit I-16. */
export function raw(markup) {
  return { [RAW]: String(markup) };
}

function isRaw(v) {
  return !!v && typeof v === "object" && RAW in v;
}

function interpolate(v) {
  if (v == null || v === false || v === true) return "";
  if (Array.isArray(v)) return v.map(interpolate).join("");
  if (isRaw(v)) return v[RAW];
  return esc(v);
}

/** Tagged template that escapes every substitution. Returns a raw node. */
export function h(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += interpolate(values[i]) + strings[i + 1];
  return raw(out);
}

/** Unwrap for innerHTML. A bare string still gets escaped on the way through. */
export function html(node) {
  return isRaw(node) ? node[RAW] : esc(node);
}

export function render(el, node) {
  if (el) el.innerHTML = html(node);
}

/* ------------------------------------------------------------------ */
/* Numbers and dates — coerced, never interpolated as free text        */
/* ------------------------------------------------------------------ */

export function fmt(n) {
  const v = Number(n);
  return Number.isFinite(v) ? v.toLocaleString("en-US") : "0";
}

export function pct(n, digits = 1) {
  const v = Number(n);
  return Number.isFinite(v) ? `${v.toFixed(digits)}%` : "—";
}

/** Clamp to a 0..100 numeric literal, safe to drop into a width declaration. */
export function width(part, total) {
  const p = Number(part);
  const t = Number(total);
  if (!Number.isFinite(p) || !Number.isFinite(t) || t <= 0) return "0";
  return Math.max(0, Math.min(100, (p / t) * 100)).toFixed(2);
}

export function heat(part, max) {
  const p = Number(part);
  const m = Number(max);
  if (!Number.isFinite(p) || !Number.isFinite(m) || m <= 0) return "0.05";
  return (0.08 + 0.62 * Math.sqrt(Math.max(0, Math.min(1, p / m)))).toFixed(3);
}

export function stamp(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return String(iso);
  return new Date(t).toISOString().replace("T", " ").slice(0, 16) + "Z";
}

export function day(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return String(iso);
  return new Date(t).toISOString().slice(0, 10);
}

export function days(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return "—";
  return `${v % 1 === 0 ? v : v.toFixed(1)}d`;
}

/* ------------------------------------------------------------------ */
/* Small shared components                                             */
/* ------------------------------------------------------------------ */

/** `kind` is caller-controlled (never probed data) but is escaped regardless. */
export function chip(label, kind, title) {
  return h`<span class="chip ${kind || ""}"${title ? h` title="${title}"` : ""}>${label}</span>`;
}

const STATE_KIND = {
  answering: "ok",
  stale: "warn",
  silent: "warn",
  expired: "bad",
  unverified: "",
};

const STATE_HELP = {
  answering: "Successful contact inside the re-probe interval (I-24).",
  stale: "No successful contact recently; still inside the retention window (I-26).",
  silent: "Gone quiet. Remediated, re-addressed, or moved — silence is not a fix.",
  expired: "Past the 180-day silence horizon (I-26); the record is due for deletion.",
  unverified: "No successful contact recorded. Indexed, not re-verified by us.",
};

export function stateChip(state) {
  return chip(state || "unknown", STATE_KIND[state] ?? "", STATE_HELP[state] || "");
}

export function sevChip(severity) {
  const s = String(severity || "").toLowerCase();
  const kind = s === "critical" || s === "high" ? "bad" : s === "medium" ? "warn" : "";
  return chip(s || "unrated", kind);
}

/**
 * I-27: lab access is not permission to publish. Every surface that shows an
 * address shows why it is (or is not) cleared, so nobody has to remember.
 */
export function discloseChip(disclosure) {
  if (!disclosure) return chip("no disclosure state", "warn");
  if (disclosure.publishable) {
    return chip("publishable", "ok", `Notification window elapsed ${stamp(disclosure.publishable_at)}`);
  }
  const why =
    disclosure.reason === "window_open"
      ? `Notified ${stamp(disclosure.notified_at)} — publishable ${stamp(disclosure.publishable_at)}`
      : "No notification attempt recorded. We notify before we publish (I-27).";
  return chip("not for publication", "warn", why);
}

export function empty(message) {
  return h`<p class="empty">${message}</p>`;
}
