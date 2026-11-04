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

// Backups: export, restore elsewhere with the same identity and data.
const backup = client.exportBackup("pw");
await assert.rejects(() => kith.KithClient.restoreBackup("restored-bad", backup, "wrong"));
const restoredFromBackup = await kith.KithClient.restoreBackup("restored-db", backup, "pw");
assert.equal(restoredFromBackup.deviceId(), client.deviceId());
assert.equal(restoredFromBackup.historyLength(id), 2);

// JSON documents: create, merge-patch, read back.
const doc = client.createDocument("acme.todo", JSON.stringify({ title: "x", n: 1 }));
assert.notEqual(client.updateDocument(doc, JSON.stringify({ n: 2, done: true })), undefined);
assert.equal(client.updateDocument(doc, JSON.stringify({ n: 2 })), undefined); // no change
assert.deepEqual(JSON.parse(client.documentJson(doc)), { title: "x", n: 2, done: true });
assert.throws(() => client.createDocument("acme.todo", "[1]"));

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
const orgP = second.createOrg();
assert.match(orgP, /^[0-9a-f]{64}$/);
second.free();
await new Promise((r) => setTimeout(r, 50));
const third = await kith.KithClient.open("smoke-db", key);
assert.equal(third.isMember(orgP), true);
assert.equal(third.isAdmin(orgP), true);
assert.deepEqual(third.groupMembers(orgP), [device]);
const link = third.createInvite(orgP, "wss://relay.example/v1/ws", 3600);
const info = kith.KithClient.parseInvite(link);
assert.equal(info.org, orgP);
assert.equal(info.relay, "wss://relay.example/v1/ws");


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
    const org = a.createOrg();
    const codes = {};
    // a admits every valid claim (an app would compare the codes first).
    a.connect(url, org, (e) => {
      if (e.type === "inviteClaimed") { codes[e.from] = e.code; a.acceptClaim(e.from); }
      evA.push(e);
    });
    await waitFor(evA, (e) => e.type === "presence" && e.online.length === 1, "a online");
    const invite = a.createInvite(org, url, 600);
    // The new device connects as pending (no certificate yet) and claims.
    b.connect(url, kith.KithClient.parseInvite(invite).org, (e) => evB.push(e));
    // Sent right after the handshake (the client queues it until then).
    const codeB = b.claimInvite(invite);
    await waitFor(evB, (e) => e.type === "joined", "b to join a's org");
    assert.equal(codes[b.deviceId()], codeB, "both screens show the same code");
    assert.equal(b.isMember(org), true);
    assert.equal(a.groupMembers(org).length, 2);
    await waitFor(evA, (e) => e.type === "presence" && e.online.length === 2, "b online with its certificate");

    // Permissions: only admins write "config"; b is an editor. b first needs the
    // policy, which arrives with its catch-up after joining.
    await waitFor(evB, (e) => e.type === "syncReceived" && e.stored > 0, "b to catch up");
    assert.equal(a.roleOf(org, a.deviceId()), "admin");
    assert.equal(b.roleOf(org, b.deviceId()), "editor");
    a.setWriteRule("config", "admin");
    await waitFor(evB, (e) => e.type === "received" && e.from === a.deviceId(), "b to get the policy change");
    assert.throws(() => b.create("config", new Uint8Array([1])), /not allowed/);
    assert.throws(() => b.setWriteRule("config", "editor"), /not an admin/);

    const objectId = a.create("acme.note", new TextEncoder().encode("from a"));
    const got = await waitFor(evB, (e) => e.type === "received" && e.objectId === objectId, "b to receive a's change");
    assert.equal(got.objectId, objectId);
    assert.equal(got.from, a.deviceId());
    assert.equal(got.isNew, true);
    assert.equal(b.historyLength(objectId), 1);

    // Documents merge across devices: concurrent patches of different keys both survive.
    const docId = a.createDocument("acme.todo", JSON.stringify({ title: "shared" }));
    await waitFor(evB, (e) => e.type === "received" && e.objectId === docId, "b to receive the document");
    a.updateDocument(docId, JSON.stringify({ owner: "ann" }));
    b.updateDocument(docId, JSON.stringify({ done: true }));
    await waitFor(evA, (e) => e.type === "received" && e.objectId === docId && e.from === b.deviceId(), "a to get b's patch");
    await waitFor(evB, (e) => e.type === "received" && e.objectId === docId && e.from === a.deviceId(), "b to get a's patch");
    const merged = { title: "shared", owner: "ann", done: true };
    assert.deepEqual(JSON.parse(a.documentJson(docId)), merged);
    assert.deepEqual(JSON.parse(b.documentJson(docId)), merged);

    b.edit(objectId, new TextEncoder().encode("from b"));
    await waitFor(evA, (e) => e.type === "received" && e.from === b.deviceId() && e.objectId === objectId, "a to receive b's edit");
    assert.equal(a.historyLength(objectId), 2);

    // A new device joins and downloads the history from an online peer (joining
    // requests it on its own); later catchUp calls work the same way.
    const evC = listen();
    const c = new kith.KithClient();
    c.connect(url, org, (e) => evC.push(e));
    c.claimInvite(a.createInvite(org, url, 600));
    await waitFor(evC, (e) => e.type === "syncReceived" && e.stored > 0, "c to join and catch up");
    assert.equal(c.historyLength(objectId), 2);
    c.catchUp();
    await waitFor(evC, (e) => e.type === "receipt" && e.delivered.length === 1, "catch-up receipt");
    assert.throws(() => new kith.KithClient().catchUp(), /not connected/);

    // Files: the reference syncs, chunks are fetched on demand and verified.
    const bytes = new Uint8Array(300 * 1024).map((_, i) => i % 251);
    const fileId = a.addFile("photo.raw", "application/octet-stream", bytes);
    await waitFor(evB, (e) => e.type === "received" && e.objectId === fileId, "b to receive the file reference");
    assert.equal(b.fileInfo(fileId).missing, 2);
    b.fetchFile(fileId);
    await waitFor(evB, (e) => e.type === "fileChunks" && e.ready.includes(fileId), "b to fetch the file");
    assert.deepEqual(b.readFile(fileId), bytes);

    // A read-restricted subgroup: b is in "finance", c is not.
    const fin = `${org}/finance`;
    a.createSubgroup("finance", [b.deviceId()]);
    await waitFor(evB, (e) => e.type === "joined" && e.org === fin, "b to join finance");
    assert.deepEqual(b.mySubgroups(org), ["finance"]);
    assert.deepEqual(c.mySubgroups(org), []);
    const ledger = a.createIn(fin, "acme.ledger", new TextEncoder().encode("q3"));
    await waitFor(evB, (e) => e.type === "received" && e.objectId === ledger, "b to receive the ledger");
    assert.equal(b.historyLength(ledger), 1);
    assert.equal(c.historyLength(ledger), 0);
    assert.throws(() => c.createIn(fin, "acme.ledger", new Uint8Array()), /not a member/);

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
