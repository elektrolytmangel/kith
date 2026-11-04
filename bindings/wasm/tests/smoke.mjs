// Loads the built npm package in Node and exercises the API end to end.
// Catches wasm-only failures (panics, wasm-opt problems) that `cargo test` can't see.
//   scripts/build-wasm.sh web && node bindings/wasm/tests/smoke.mjs bindings/wasm/pkg
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";
// Node has no IndexedDB; this provides a spec-compliant one on globalThis.
await import("fake-indexeddb/auto");

const dir = resolve(process.argv[2] ?? "bindings/wasm/pkg");
const kith = await import(`${dir}/kith.js`);
await kith.default({ module_or_path: readFileSync(`${dir}/kith_bg.wasm`) });

const client = new kith.KithClient();
assert.match(client.deviceId(), /^[0-9a-f]{64}$/);
const id = client.create("acme.note", new TextEncoder().encode("hello"));
client.edit(id, new TextEncoder().encode("hello world"));
assert.equal(client.historyLength(id), 2);
assert.throws(() => client.edit("not-hex", new Uint8Array()));

// Key restore: same secret key, same device identity.
const restored = kith.KithClient.withSecretKey(client.secretKey());
assert.equal(restored.deviceId(), client.deviceId());
assert.notEqual(new kith.KithClient().deviceId(), client.deviceId());
assert.throws(() => kith.KithClient.withSecretKey(new Uint8Array(31)));

// Persistence in IndexedDB: same db name + key => same identity and data.
const key = kith.generateSecretKey();
assert.equal(key.length, 32);
const first = await kith.KithClient.open("smoke-db", key);
const oid = first.create("acme.note", new TextEncoder().encode("one"));
first.edit(oid, new TextEncoder().encode("two"));
const device = first.deviceId();
first.free();
await new Promise((r) => setTimeout(r, 50)); // let the queued writes commit
const second = await kith.KithClient.open("smoke-db", key);
assert.equal(second.deviceId(), device);
assert.equal(second.historyLength(oid), 2);
second.edit(oid, new TextEncoder().encode("three"));
assert.equal(second.historyLength(oid), 3);
await assert.rejects(() => kith.KithClient.open("smoke-db", new Uint8Array(5)));
const other = await kith.KithClient.open("other-db", key);
assert.equal(other.historyLength(oid), 0); // separate database, no data

console.log(`ok: kith-wasm ${kith.version()}`);
