/**
 * I-20: no proxying of user traffic through third-party hosts, in any phase.
 *
 * This is a structural suite on purpose. I-20 is a statement about code that
 * does not exist, and you cannot exercise an absent code path — so instead the
 * source tree is read and every outbound request site is checked against a
 * declared inventory. A new `fetch()` in the Worker, or a browser request whose
 * URL is built from a corpus host, fails this suite until someone adds it to
 * the inventory and explains why it is not a relay.
 *
 * The Worker inventory is deliberately fine-grained (file, URL expression,
 * method): the regression that would matter — forwarding a researcher's request
 * to a discovered host — has to appear either as a new call site or as a changed
 * URL expression in `safeGet`, and both fail here. The client assertions are
 * shape-based rather than verbatim, because the static UIs churn for reasons
 * that have nothing to do with I-20.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { DISCOVERY_PROFILES, SERVICES } from "../src/lib/services.js";
import { check, section, finish } from "./_harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..", "..");
const WORKER_SRC = path.join(ROOT, "worker", "src");

function walk(dir, ext = ".js") {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p, ext));
    else if (entry.name.endsWith(ext)) out.push(p);
  }
  return out.sort();
}

const rel = (p) => path.relative(ROOT, p);

/**
 * Mask comments, and optionally string bodies, with a real scanner rather than
 * regexes.
 *
 * A regex pass is not good enough here and the failure is not theoretical: the
 * Accept header in services.js contains a wildcard media range whose asterisk
 * and slash a block-comment regex reads as a comment terminator, silently
 * swallowing the rest of the file — an I-20 grep that passes because it saw
 * nothing. Strings must be masked too, because the remediation prose
 * legitimately says "front it with a reverse proxy".
 */
function mask(src, { keepStrings = false } = {}) {
  let out = "";
  let prev = "";
  let i = 0;
  const n = src.length;
  const regexCanStart = () => prev === "" || "(,=:[!&|?{};+-*%~^<>".includes(prev);
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === "/" && c2 === "/") {
      while (i < n && src[i] !== "\n") i++;
      out += " ";
      continue;
    }
    if (c === "/" && c2 === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      out += " ";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      let raw = c;
      i++;
      while (i < n) {
        if (src[i] === "\\") {
          raw += src[i] + (src[i + 1] || "");
          i += 2;
          continue;
        }
        if (src[i] === quote) {
          raw += quote;
          i++;
          break;
        }
        raw += src[i];
        i++;
      }
      out += keepStrings ? raw : '""';
      prev = '"';
      continue;
    }
    if (c === "/" && regexCanStart()) {
      let inClass = false;
      i++;
      while (i < n) {
        const d = src[i];
        if (d === "\\") {
          i += 2;
          continue;
        }
        if (d === "[") inClass = true;
        else if (d === "]") inClass = false;
        else if (d === "/" && !inClass) {
          i++;
          break;
        } else if (d === "\n") break;
        i++;
      }
      while (i < n && /[gimsuyd]/.test(src[i])) i++;
      out += "/RE/";
      prev = ")";
      continue;
    }
    out += c;
    if (!/\s/.test(c)) prev = c;
    i++;
  }
  return out;
}

/** First argument of the call whose open paren sits at `from`, paren-balanced. */
function firstArg(clean, from) {
  let depth = 1;
  let i = from;
  let arg = "";
  while (i < clean.length) {
    const ch = clean[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    if (depth === 0 || (ch === "," && depth === 1)) break;
    arg += ch;
    i++;
  }
  return { arg: arg.trim(), end: i };
}

/**
 * Every `fetch(` call that is not the Worker's own `async fetch(request…)`
 * export, with its first argument and declared method.
 */
function fetchCallSites(src) {
  const clean = mask(src, { keepStrings: true });
  const sites = [];
  for (const m of clean.matchAll(/(?<![.\w$])fetch\s*\(/g)) {
    if (/\basync\s*$/.test(clean.slice(Math.max(0, m.index - 12), m.index))) continue;
    const { arg, end } = firstArg(clean, m.index + m[0].length);
    const method = /method\s*:\s*"([A-Z]+)"/.exec(clean.slice(end, end + 400));
    sites.push({ arg, method: method ? method[1] : "GET" });
  }
  return sites;
}

/* ------------------------------------------------------------------ */
section("[P0] the masker itself works (a broken grep is worse than none)");

{
  const sample = 'const a = "text/html, */*;q=0.5"; // note\nfetch(url);\nconst r = /["\']/;\n';
  await check("a string containing */ does not swallow the rest of the file", () => {
    assert.deepEqual(fetchCallSites(sample), [{ arg: "url", method: "GET" }]);
  });
  await check("prose inside a string is masked, code is not", () => {
    const masked = mask('const x = "a reverse proxy"; const proxyFlag = 1;');
    assert.ok(!masked.includes("reverse proxy"));
    assert.ok(masked.includes("proxyFlag"));
  });
}

/* ------------------------------------------------------------------ */
section("[P1] every outbound request site in the Worker is inventoried");

/**
 * The complete set of things this Worker may talk to. Three of the four are
 * infrastructure we own or a database we query about a *version string*;
 * exactly one reaches a third-party target, and that one is `safeGet` —
 * read-only GET, allowlisted port, fixed metadata path (I-1, I-2, I-5).
 */
const FETCH_INVENTORY = {
  "worker/src/lib/access.js": [
    { arg: "url", method: "GET", why: "Cloudflare Access signing certs" },
  ],
  "worker/src/lib/turnstile.js": [
    {
      arg: '"https://challenges.cloudflare.com/turnstile/v0/siteverify"',
      method: "POST",
      why: "Turnstile siteverify — literal URL, no host value can reach it",
    },
  ],
  "worker/src/lib/osv.js": [
    {
      arg: "OSV_URL",
      method: "POST",
      why: "OSV.dev version lookup — constant URL, body is a version string",
    },
  ],
  "worker/src/lib/services.js": [
    { arg: "url", method: "GET", why: "safeGet — the only fetch that reaches a probed target" },
  ],
};

{
  const found = {};
  for (const file of walk(WORKER_SRC)) {
    const sites = fetchCallSites(fs.readFileSync(file, "utf8"));
    if (sites.length) found[rel(file)] = sites;
  }

  await check("no Worker file makes an outbound request outside the inventory", () => {
    const unexpected = Object.keys(found).filter((f) => !FETCH_INVENTORY[f]);
    assert.deepEqual(
      unexpected,
      [],
      `undeclared outbound request site(s) in: ${unexpected.join(", ")}. ` +
        "A new fetch is how a relay arrives — declare it or remove it."
    );
  });

  for (const [file, expected] of Object.entries(FETCH_INVENTORY)) {
    await check(`${file}: call sites match the inventory`, () => {
      const sites = found[file] || [];
      assert.equal(sites.length, expected.length, `expected ${expected.length} fetch call(s)`);
      sites.forEach((site, i) => {
        assert.equal(site.arg, expected[i].arg, `URL expression changed (${expected[i].why})`);
        assert.equal(site.method, expected[i].method, `HTTP method changed (${expected[i].why})`);
      });
    });
  }

  await check("the single target-facing fetch is a GET (I-1)", () => {
    assert.equal(found["worker/src/lib/services.js"][0].method, "GET");
  });

  await check("the target URL is built by baseUrl() from an http origin only", () => {
    const svc = mask(fs.readFileSync(path.join(WORKER_SRC, "lib", "services.js"), "utf8"), {
      keepStrings: true,
    });
    // A scheme that came from the target (or from a caller) is how a probe
    // becomes a request to somewhere else entirely.
    assert.ok(!/https?:\/\/\$\{\s*(scheme|proto|protocol)/.test(svc));
    assert.match(svc, /function baseUrl\(host, port\)/);
    let calls = 0;
    for (const m of svc.matchAll(/(?<!function )(?<![.\w$])safeGet\s*\(/g)) {
      const { arg } = firstArg(svc, m.index + m[0].length);
      calls++;
      assert.match(arg, /^`\$\{base\}/, `safeGet called with a URL not derived from baseUrl(): ${arg}`);
    }
    assert.ok(calls >= 2, "expected the confirm and exposure probes to call safeGet");
  });

  await check("the production TCP destination is the canonical consumed permit only", () => {
    const socket = fs.readFileSync(path.join(WORKER_SRC, "lib", "socket_probe.js"), "utf8");
    assert.match(socket, /import\("cloudflare:sockets"\)/);
    assert.match(socket, /connect\(\s*\{ hostname: canonical, port: Number\(port\) \}/);
    assert.match(socket, /canonical !== ip \|\| isPrivateOrLocal\(canonical\)/);
    assert.match(socket, /resolvePort\(service, port\)/);
    assert.match(socket, /reviewedPaths\(service\)\.has\(path\)/);
    assert.ok(!/connect\(\s*\{[^}]*hostname:\s*(body|request|url|target)/.test(socket));
  });
}

/* ------------------------------------------------------------------ */
section("[P2] the researcher-facing surface cannot emit a request at all");

{
  const labSrc = fs.readFileSync(path.join(WORKER_SRC, "lib", "lab.js"), "utf8");
  const indexSrc = fs.readFileSync(path.join(WORKER_SRC, "index.js"), "utf8");

  await check("lab.js contains no fetch call — a lab query can never become a probe", () => {
    assert.deepEqual(fetchCallSites(labSrc), []);
  });

  await check("index.js makes no outbound request of its own", () => {
    assert.deepEqual(fetchCallSites(indexSrc), []);
  });

  await check("no lab route reads a caller-supplied URL, host or upstream", () => {
    for (const token of ["url", "endpoint", "upstream", "host", "origin", "callback", "proxy"]) {
      assert.ok(
        !new RegExp(`get\\(\\s*["'\`]${token}["'\`]\\s*\\)`).test(labSrc),
        `a lab route reads a '${token}' parameter — that is the shape of a forwarder`
      );
    }
  });
}

/* ------------------------------------------------------------------ */
section("[P3] no relay machinery anywhere in the Worker");

/**
 * Tokens that appear only when something is being forwarded or streamed
 * through. Checked against masked code, so remediation advice does not trip it.
 */
const RELAY_TOKENS = [
  "proxy",
  "relay",
  "passthrough",
  "pipeTo",
  "pipeThrough",
  "TransformStream",
  "WebSocketPair",
  "webSocket",
  "new Request",
  "upstream",
  "EventSource",
];

{
  for (const file of walk(WORKER_SRC)) {
    const code = mask(fs.readFileSync(file, "utf8"));
    await check(`${rel(file)}: no forwarding primitives in code`, () => {
      const hits = RELAY_TOKENS.filter((t) => code.includes(t));
      assert.deepEqual(hits, [], `relay-shaped construct(s): ${hits.join(", ")}`);
    });
  }
}

{
  // `return new Response(upstream.body)` is the canonical two-line proxy. Every
  // Response we construct is built from our own serialised data instead.
  const RESPONSE_INVENTORY = {
    // Internal Durable Object protocol; body is always JSON.stringify(body).
    "worker/src/control_plane.js": ["JSON.stringify(body)"],
    "worker/src/lib/cors.js": [
      "JSON.stringify(data, null, 0)",
      "JSON.stringify(data, null, 0)",
      "null",
    ],
  };
  const found = {};
  for (const file of walk(WORKER_SRC)) {
    const code = mask(fs.readFileSync(file, "utf8"), { keepStrings: true });
    const args = [...code.matchAll(/new Response\s*\(/g)].map(
      (m) => firstArg(code, m.index + m[0].length).arg
    );
    if (args.length) found[rel(file)] = args;
  }
  await check("no Response is constructed from an upstream body", () => {
    assert.deepEqual(Object.keys(found).sort(), Object.keys(RESPONSE_INVENTORY).sort());
    for (const [file, args] of Object.entries(RESPONSE_INVENTORY)) {
      assert.deepEqual(found[file], args);
    }
  });
}

/* ------------------------------------------------------------------ */
section("[P4] I-2: probe paths stay metadata/health/version/listing only");

{
  // The tier-1 table in docs/SECURITY.md, verbatim. Widening it is an
  // amendment, not a refactor.
  const ALLOWED_PATHS = new Set([
    "/api/version",
    "/api/tags",
    "/api/status",
    "/api/jobs/",
    "/tree",
    "/",
    "/api/ps",
    "/api/config",
    "/v1/models",
    "/health/liveliness",
    "/system_stats",
    "/config",
    "/health",
    "/v2",
    "/data/plugins_listing",
    "/leakycompute-owned-canary",
  ]);
  const paths = [];
  for (const svc of Object.values(SERVICES)) {
    for (const step of svc.confirm || []) if (step.path) paths.push(step.path);
    if (svc.exposure?.path) paths.push(svc.exposure.path);
  }
  for (const profile of Object.values(DISCOVERY_PROFILES)) paths.push(profile.path);

  await check("every registered probe path is in the I-2 table", () => {
    const extra = [...new Set(paths)].filter((p) => !ALLOWED_PATHS.has(p));
    assert.deepEqual(extra, [], `probe path(s) outside the I-2 table: ${extra.join(", ")}`);
    assert.ok(paths.length >= 6, "expected the tier-1 probe paths to be registered");
  });

  await check("no registered path could make a target do something (I-3)", () => {
    for (const p of paths) {
      assert.ok(
        !/(generate|chat|completion|pull|push|create|delete|submit|run|exec|kernel|terminal|upload|contents)/i.test(
          p
        ),
        `probe path '${p}' looks like an action, not a read`
      );
    }
  });
}

/* ------------------------------------------------------------------ */
section("[P5] the browser clients never build a request from a corpus host");

/**
 * A relay does not have to live in the Worker: a page that fetched a corpus
 * host straight from the researcher's browser is the same behaviour with a hop
 * removed. Asserted by shape rather than by a verbatim inventory, because these
 * files change for UI reasons constantly and a brittle assertion here would be
 * deleted rather than fixed.
 */
const HOST_ISH = /\b(ip|ips|host|hosts|addr|address|target|hit|row|record|endpoint|node)\b/i;

{
  const clientDirs = [path.join(ROOT, "public", "js"), path.join(ROOT, "lab", "js")];
  const files = clientDirs.filter((d) => fs.existsSync(d)).flatMap((d) => walk(d));

  await check("client sources were found (an empty scan must not pass)", () => {
    assert.ok(files.length >= 2, `expected client JS, found ${files.length} file(s)`);
  });

  for (const file of files) {
    const raw = fs.readFileSync(file, "utf8");
    const code = mask(raw, { keepStrings: true });
    const sites = fetchCallSites(raw);

    await check(`${rel(file)}: no fetch URL is built from a host value`, () => {
      for (const site of sites) {
        assert.ok(
          !HOST_ISH.test(site.arg),
          `request URL derived from a host value: fetch(${site.arg})`
        );
      }
    });

    await check(`${rel(file)}: no absolute URL with an interpolated authority`, () => {
      // `http://${h}:${p}` — the only way a browser reaches a discovered host.
      assert.ok(
        !/https?:\/\/\$\{/.test(code),
        "builds an absolute URL from a variable authority"
      );
      assert.ok(
        !/["'`]https?:\/\/["'`]\s*\+/.test(code),
        "concatenates an absolute URL from a variable authority"
      );
    });

    await check(`${rel(file)}: no tier-1 service port in a URL`, () => {
      for (const port of ["11434", "11435", "8265", "8888", "8889"]) {
        assert.ok(
          !new RegExp(`:${port}\\b`).test(code),
          `client references service port ${port} — a browser has no business dialling one`
        );
      }
    });

    await check(`${rel(file)}: no forwarding primitives`, () => {
      const masked = mask(raw);
      const hits = ["WebSocket", "EventSource", "sendBeacon", "XMLHttpRequest"].filter((t) =>
        masked.includes(t)
      );
      assert.deepEqual(hits, [], `client transport(s) outside fetch-to-our-API: ${hits.join(", ")}`);
    });
  }
}

/* ------------------------------------------------------------------ */
section("[P6] no route, flag or handler offers a relay");

{
  const indexSrc = fs.readFileSync(path.join(WORKER_SRC, "index.js"), "utf8");
  const labSrc = fs.readFileSync(path.join(WORKER_SRC, "lib", "lab.js"), "utf8");
  const routePaths = [
    ...[...indexSrc.matchAll(/path === "([^"]+)"/g)].map((m) => m[1]),
    ...[...labSrc.matchAll(/path: `\$\{ROUTE_PREFIX\}\/([a-z]+)`/g)].map((m) => `/${m[1]}`),
  ];

  await check("no route name suggests forwarding, chatting or execution", () => {
    const bad = routePaths.filter((p) =>
      /(chat|prompt|proxy|relay|forward|exec|run|shell|kernel|generate|completion)/i.test(p)
    );
    assert.deepEqual(bad, [], `route(s) that would be a relay by name: ${bad.join(", ")}`);
    assert.ok(routePaths.length >= 10, "route extraction found suspiciously few routes");
  });

  await check("the lab still advertises chat as disabled", () => {
    assert.match(indexSrc, /chat_enabled:\s*false/);
    assert.ok(!/chat_enabled:\s*true/.test(indexSrc));
  });
}

/* ------------------------------------------------------------------ */
section("[P7] probe-request hygiene: I-6 redirects, I-7 body cap, I-23 identity");

{
  const svcRaw = fs.readFileSync(path.join(WORKER_SRC, "lib", "services.js"), "utf8");
  const socketRaw = fs.readFileSync(path.join(WORKER_SRC, "lib", "socket_probe.js"), "utf8");

  await check("I-6: the probe never follows a redirect off the target", () => {
    assert.match(svcRaw, /redirect:\s*"manual"/);
    assert.ok(
      !/redirect:\s*"(follow|error)"/.test(svcRaw),
      "a followed redirect lets a target bounce our probe to a third host"
    );
    assert.ok(!/location[^\n]{0,120}(socketGet|connect)\s*\(/i.test(socketRaw));
  });

  await check("I-7: the response body is read with a hard cap", () => {
    assert.match(svcRaw, /maxBytes\s*=\s*32\s*\*\s*1024/);
    assert.match(svcRaw, /while\s*\(received\s*<\s*maxBytes\)/);
    assert.match(socketRaw, /const BODY_CAP = 32 \* 1024/);
    assert.match(socketRaw, /received < HEADER_CAP \+ maxBytes/);
  });

  await check("I-23: the Worker probes under an identifiable SafeProbe agent", () => {
    const ua = /"User-Agent":\s*"([^"]+)"/.exec(svcRaw);
    assert.ok(ua, "the probe sends no User-Agent at all");
    assert.match(ua[1], /^LeakyCompute-SafeProbe\//);
    assert.match(socketRaw, /const USER_AGENT = "LeakyCompute-SafeProbe\//);
    assert.match(socketRaw, /`GET \$\{path\} HTTP\/1\.0/);
  });
}

{
  /**
   * I-23's promise is that an operator who finds us in their logs can identify
   * us in one search. Several tools emit probes, so what has to hold across all
   * of them is the searchable prefix — asserted here so a new script cannot
   * start probing anonymously.
   *
   * The stronger claim — that every agent aimed at a *target* is the single
   * `SafeProbe` name /scanning publishes — is asserted in governance_gates.py,
   * which can import the runner and read the constant it actually sends rather
   * than pattern-matching source text.
   */
  const scriptsDir = path.join(ROOT, "scripts");
  const agents = new Set();
  const sources = [
    ...walk(WORKER_SRC),
    ...(fs.existsSync(scriptsDir) ? walk(scriptsDir, ".py") : []),
  ];
  for (const file of sources) {
    const src = fs.readFileSync(file, "utf8");
    for (const m of src.matchAll(/["']User-Agent["']\s*:\s*["']([^"']+)["']/g)) agents.add(m[1]);
    for (const m of src.matchAll(/USER_AGENT\s*=\s*["']([^"']+)["']/g)) agents.add(m[1]);
  }

  await check("every agent this project probes under is attributable to it", () => {
    assert.ok(agents.size > 0, "no User-Agent found anywhere — extraction is broken");
    const anonymous = [...agents].filter((a) => !a.startsWith("LeakyCompute-"));
    assert.deepEqual(anonymous, [], `unattributable probe agent(s): ${anonymous.join(", ")}`);
  });
}

finish();
