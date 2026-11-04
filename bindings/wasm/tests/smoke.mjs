// Loads the built npm package in Node and exercises the API end to end.
// Catches wasm-only failures (panics, wasm-opt problems) that `cargo test` can't see.
//   scripts/build-wasm.sh web && node bindings/wasm/tests/smoke.mjs bindings/wasm/pkg
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
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

// The MLS group state is persisted in the same database.
assert.equal(second.isMember("org-p"), false);
second.createGroup("org-p");
second.free();
await new Promise((r) => setTimeout(r, 50));
const third = await kith.KithClient.open("smoke-db", key);
assert.equal(third.isMember("org-p"), true);
assert.deepEqual(third.groupMembers("org-p"), [device]);


// Live sync through a real relay. Needs the relay binary:
//   cargo build -p kith-relay-server && KITH_RELAY_BIN=target/debug/kith-relay node ...
if (process.env.KITH_RELAY_BIN) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const relay = spawn(process.env.KITH_RELAY_BIN, [], {
    env: { ...process.env, KITH_RELAY_ADDR: `127.0.0.1:${port}`, RUST_LOG: "warn" },
    stdio: "inherit",
  });
  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) break;
      } catch {}
      assert.ok(i < 100, "relay did not start");
      await new Promise((r) => setTimeout(r, 100));
    }
    const url = `ws://127.0.0.1:${port}/v1/ws`;
    const waitFor = (events, pred, what) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`timed out waiting for ${what}`)), 5000);
        const check = () => {
          const hit = events.find(pred);
          if (hit) { clearTimeout(t); resolve(hit); }
          else events.waiters.push(check);
        };
        check();
      });
    const listen = () => {
      const events = [];
      events.waiters = [];
      events.push = (e) => { Array.prototype.push.call(events, e); events.waiters.splice(0).forEach((f) => f()); };
      return events;
    };

    const evA = listen(), evB = listen();
    const a = new kith.KithClient(), b = new kith.KithClient();
    a.createGroup("org");
    // a admits every device that asks (an app would ask the user first).
    a.connect(url, "org", (e) => {
      if (e.type === "joinRequested") a.addMember(e.keyPackage);
      evA.push(e);
    });
    b.connect(url, "org", (e) => evB.push(e));
    await waitFor(evA, (e) => e.type === "presence" && e.online.length === 2, "both devices online");
    b.requestJoin(a.deviceId());
    await waitFor(evB, (e) => e.type === "joined", "b to join a's group");
    assert.equal(b.isMember("org"), true);
    assert.equal(a.groupMembers("org").length, 2);

    const objectId = a.create("acme.note", new TextEncoder().encode("from a"));
    const got = await waitFor(evB, (e) => e.type === "received", "b to receive a's change");
    assert.equal(got.objectId, objectId);
    assert.equal(got.from, a.deviceId());
    assert.equal(got.isNew, true);
    assert.equal(b.historyLength(objectId), 1);

    b.edit(objectId, new TextEncoder().encode("from b"));
    await waitFor(evA, (e) => e.type === "received" && e.from === b.deviceId(), "a to receive b's edit");
    assert.equal(a.historyLength(objectId), 2);

    // A new device joins and downloads the history from an online peer (joining
    // requests it on its own); later catchUp calls work the same way.
    const evC = listen();
    const c = new kith.KithClient();
    c.connect(url, "org", (e) => evC.push(e));
    await waitFor(evC, (e) => e.type === "presence" && e.online.length === 3, "c online");
    c.requestJoin(a.deviceId());
    await waitFor(evC, (e) => e.type === "syncReceived" && e.stored > 0, "c to join and catch up");
    assert.equal(c.historyLength(objectId), 2);
    c.catchUp();
    await waitFor(evC, (e) => e.type === "receipt" && e.delivered.length === 1, "catch-up receipt");
    assert.throws(() => new kith.KithClient().catchUp(), /not connected/);

    a.disconnect();
    b.disconnect();
    c.disconnect();
    console.log("ok: live sync through the relay");
  } finally {
    relay.kill();
  }
} else {
  console.log("skipped: live sync (set KITH_RELAY_BIN to the kith-relay binary)");
}

console.log(`ok: kith-wasm ${kith.version()}`);
