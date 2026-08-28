import assert from "node:assert/strict";
import {
  completionOutcome,
  pinnedTransport,
  runDiscoveryPermit,
  runHostedPermit,
  socketGet,
} from "../src/lib/socket_probe.js";

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (error) {
    failures++;
    console.log(`  FAIL ${name}\n       ${error.stack || error.message}`);
  }
}

function fakeSocket(response, capture = {}) {
  const bytes = new TextEncoder().encode(response);
  return {
    opened: Promise.resolve({ remoteAddress: "8.8.8.8:11434" }),
    writable: new WritableStream({
      write(chunk) { capture.request = new TextDecoder().decode(chunk); },
    }),
    readable: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }),
    async close() { capture.closed = true; },
  };
}

console.log("\n[SP1] address-pinned socket boundary");

await check("private targets are rejected before connect()", async () => {
  let called = false;
  const result = await socketGet(
    { ip: "127.0.0.1", port: 11434, path: "/api/version", service: "ollama" },
    { connectImpl: () => { called = true; } }
  );
  assert.equal(result.error_class, "authorization_error");
  assert.equal(called, false);
});

await check("caller-selected state-changing paths cannot cross the permit", async () => {
  let called = false;
  const transport = pinnedTransport(
    { ip: "8.8.8.8", port: 11434, service: "ollama" },
    { connectImpl: () => { called = true; } }
  );
  const result = await transport("http://8.8.8.8:11434/api/generate", { timeoutMs: 50 });
  assert.equal(result.error, "path_not_allowed");
  assert.equal(called, false);
});

await check("the emitted request is one attributable GET to the exact permit destination", async () => {
  const capture = {};
  const result = await socketGet(
    { ip: "8.8.8.8", port: 11434, path: "/api/version", service: "ollama" },
    {
      connectImpl(address, options) {
        capture.address = address;
        capture.options = options;
        return fakeSocket("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"version\":\"1.2.3\"}", capture);
      },
    }
  );
  assert.equal(result.ok, true);
  assert.deepEqual(capture.address, { hostname: "8.8.8.8", port: 11434 });
  assert.equal(capture.options.secureTransport, "off");
  assert.match(capture.request, /^GET \/api\/version HTTP\/1\.0\r\n/);
  assert.match(capture.request, /User-Agent: LeakyCompute-SafeProbe\/3\.0/);
  assert.doesNotMatch(capture.request, /POST|Content-Length/i);
  assert.equal(capture.closed, true);
});

await check("response bodies are capped at 32 KiB", async () => {
  const body = "x".repeat(40 * 1024);
  const result = await socketGet(
    { ip: "8.8.4.4", port: 8888, path: "/", service: "jupyter" },
    { connectImpl: () => fakeSocket(`HTTP/1.0 200 OK\r\n\r\n${body}`) }
  );
  assert.equal(result.text.length, 32 * 1024);
});

await check("platform policy failures cannot become a clean target verdict", async () => {
  const result = await socketGet(
    { ip: "8.8.8.8", port: 11434, path: "/api/version", service: "ollama" },
    {
      connectImpl: () => ({
        opened: Promise.reject(new Error("proxy request failed, cannot connect to the specified address")),
        writable: new WritableStream(),
        readable: new ReadableStream(),
        async close() {},
      }),
    }
  );
  assert.equal(result.error_class, "platform_error");
  assert.equal(completionOutcome(result), "platform_error");
});

await check("a hosted fingerprint uses only its reviewed confirm and exposure paths", async () => {
  const captures = [];
  const responses = [
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"version\":\"0.9.0\"}",
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"models\":[]}",
  ];
  const run = await runHostedPermit(
    { ip: "8.8.8.8", port: 11434, service: "ollama" },
    {
      connectImpl(address) {
        const capture = { address };
        captures.push(capture);
        return fakeSocket(responses.shift(), capture);
      },
    }
  );
  assert.equal(run.result.detected, true);
  assert.equal(run.result.exposed, true);
  assert.deepEqual(
    captures.map((capture) => /^GET ([^ ]+)/.exec(capture.request)?.[1]),
    ["/api/version", "/api/tags"]
  );
});

await check("a discovery profile remains authorized when the service is also hosted", async () => {
  const capture = {};
  const run = await runDiscoveryPermit(
    { ip: "8.8.8.8", port: 11434, service: "ollama" },
    {
      connectImpl: () => fakeSocket(
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"models\":[]}",
        capture
      ),
    }
  );
  assert.equal(run.result.exposed, true);
  assert.match(capture.request, /^GET \/api\/ps HTTP\/1\.0\r\n/);
});

await check("an unrelated HTTP 200 is not classified as an exposed AI service", async () => {
  const run = await runDiscoveryPermit(
    { ip: "8.8.4.4", port: 8888, service: "jupyter" },
    { connectImpl: () => fakeSocket("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome</h1>") }
  );
  assert.equal(run.result.answered, true);
  assert.equal(run.result.exposed, false);
});

await check("hostile non-array model JSON cannot crash an emitted probe", async () => {
  const run = await runDiscoveryPermit(
    { ip: "8.8.8.8", port: 11434, service: "ollama" },
    { connectImpl: () => fakeSocket("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"models\":{}}") }
  );
  assert.equal(run.result.exposed, false);
  assert.deepEqual(run.result.models, []);
});

await check("the owned canary requires its exact fixed path and response marker", async () => {
  const capture = {};
  const run = await runDiscoveryPermit(
    {
      ip: "93.184.216.99",
      port: 80,
      service: "owned_canary",
      canary_hostname: "canary.example.test",
    },
    {
      connectImpl: (address, options) => {
        capture.address = address;
        capture.options = options;
        return fakeSocket(
          "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" +
          '{"leakycompute_canary":"owned"}',
          capture
        );
      },
    }
  );
  assert.equal(run.result.exposed, true);
  assert.equal(run.result.canary_marker, "owned");
  assert.equal(run.result.destination_pinned, true);
  assert.deepEqual(capture.address, { hostname: "93.184.216.99", port: 80 });
  assert.deepEqual(capture.options, { secureTransport: "off", allowHalfOpen: false });
  assert.match(capture.request, /^GET \/leakycompute-owned-canary HTTP\/1\.0\r\n/);
  assert.match(capture.request, /Host: canary\.example\.test:80\r\n/);
  assert.equal(capture.closed, true);
});

if (failures) {
  console.error(`\n${failures} socket-probe assertion(s) failed`);
  process.exit(1);
}
console.log("\nsocket-probe tests passed (fake sockets only)");
