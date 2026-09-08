import assert from "node:assert/strict";
import {
  getLaneCursors,
  setLaneCursor,
  setLaneCursors,
} from "../src/lib/discovery.js";
import { check, section, finish, makeKV } from "./_harness.mjs";

section("[C1] lane cursors preserve page tails without multiplying KV writes");

await check("a cursor batch is persisted with one KV write", async () => {
  const kv = makeKV();
  const originalPut = kv.put.bind(kv);
  let puts = 0;
  kv.put = async (...args) => {
    puts += 1;
    return originalPut(...args);
  };
  const env = { KV: kv };

  const saved = await setLaneCursors(env, [
    { lane: "jupyter", page: 3, offset: 40, observed: 100 },
    { lane: "litellm", page: 8, offset: 30, observed: 100 },
  ]);

  assert.equal(puts, 1);
  assert.equal(saved.length, 2);
  assert.deepEqual(await getLaneCursors(env), {
    jupyter: {
      page: 3,
      offset: 40,
      exhausted: false,
      observed_last_run: 100,
      updated_at: saved[0].updated_at,
    },
    litellm: {
      page: 8,
      offset: 30,
      exhausted: false,
      observed_last_run: 100,
      updated_at: saved[0].updated_at,
    },
  });
});

await check("invalid offsets fail closed to the start of the retained page", async () => {
  const env = { KV: makeKV() };
  const saved = await setLaneCursor(env, "ray", {
    page: 2,
    offset: -10,
    observed: 100,
  });
  assert.equal(saved.page, 2);
  assert.equal(saved.offset, 0);
});

finish();
