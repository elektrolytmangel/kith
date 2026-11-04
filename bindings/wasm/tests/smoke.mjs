// Loads the built npm package in Node and exercises the API end to end.
// Catches wasm-only failures (panics, wasm-opt problems) that `cargo test` can't see.
//   scripts/build-wasm.sh web && node bindings/wasm/tests/smoke.mjs bindings/wasm/pkg
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

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
console.log(`ok: kith-wasm ${kith.version()}`);
