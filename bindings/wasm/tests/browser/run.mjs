// Real-browser tests of the built npm package (Chromium via Playwright).
//   scripts/build-wasm.sh web && cargo build -p kith-relay-server
//   npm ci --prefix bindings/wasm/tests/browser
//   KITH_RELAY_BIN=target/debug/kith-relay node bindings/wasm/tests/browser/run.mjs
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import assert from "node:assert/strict";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = resolve(process.argv[2] ?? join(here, "../../pkg"));
const relayBin = process.env.KITH_RELAY_BIN;
assert.ok(relayBin, "set KITH_RELAY_BIN to the kith-relay binary");

// --- static server with a strict CSP ------------------------------------------------
const types = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html" };
const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self' ws://127.0.0.1:*",
].join("; ");
const server = createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  const file = path.startsWith("/pkg/")
    ? join(pkg, path.slice(5))
    : join(here, path === "/" ? "index.html" : path.slice(1));
  if (!file.startsWith(pkg) && !file.startsWith(here) || !existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  const ext = file.slice(file.lastIndexOf("."));
  res.writeHead(200, {
    "content-type": types[ext] ?? "application/octet-stream",
    "content-security-policy": csp,
  });
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${server.address().port}`;

// --- relay (can be restarted on the same port) ----------------------------------------
const relayPort = 20000 + Math.floor(Math.random() * 20000);
const relayUrl = `ws://127.0.0.1:${relayPort}/v1/ws`;
let relay;
async function startRelay() {
  relay = spawn(relayBin, [], {
    env: { ...process.env, KITH_RELAY_ADDR: `127.0.0.1:${relayPort}`, RUST_LOG: "warn" },
    stdio: "inherit",
  });
  for (let i = 0; ; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${relayPort}/healthz`)).ok) return;
    } catch {}
    assert.ok(i < 100, "relay did not start");
    await new Promise((r) => setTimeout(r, 100));
  }
}
async function stopRelay() {
  const done = new Promise((r) => relay.once("exit", r));
  relay.kill();
  await done;
}
await startRelay();

const browser = await chromium.launch({ args: ["--no-sandbox"] });
const failures = [];
const test = async (name, fn) => {
  const t0 = Date.now();
  try {
    await fn();
    console.log(`ok   ${name} (${Date.now() - t0} ms)`);
  } catch (e) {
    failures.push(name);
    console.log(`FAIL ${name}\n${e.stack ?? e}`);
  }
};

async function newPage(context) {
  const page = await context.newPage();
  const problems = [];
  page.on("pageerror", (e) => problems.push(String(e)));
  page.on("console", (m) => m.type() === "error" && problems.push(m.text()));
  await page.goto(origin);
  await page.waitForFunction(() => window.ready === true, null, { timeout: 15000 });
  page.problems = problems;
  return page;
}
// Page-side checks are plain functions with arguments (the page has no 'unsafe-eval').
const hasEvent = (page, type, extra = {}) =>
  page.waitForFunction(
    ([type, extra]) =>
      window.t.events.some(
        (e) => e.type === type && Object.entries(extra).every(([k, v]) => e[k] === v),
      ),
    [type, extra],
    { timeout: 20000 },
  );

// ---------------------------------------------------------------------------------------
// req: REQ-PLAT-009
await test("package loads under a strict CSP (no unsafe-eval)", async () => {
  const ctx = await browser.newContext();
  const page = await newPage(ctx);
  assert.deepEqual(page.problems, []);
  assert.equal(typeof (await page.evaluate(() => window.t.kith.version())), "string");
  await ctx.close();
});

// req: REQ-DATA-007
await test("data and identity survive a reload", async () => {
  const ctx = await browser.newContext();
  const page = await newPage(ctx);
  const id = await page.evaluate(() => window.t.openClient("persist"));
  const doc = await page.evaluate(() => {
    const d = window.t.c.createDocument("acme.todo", JSON.stringify({ a: 1 }));
    window.t.c.updateDocument(d, JSON.stringify({ b: 2 }));
    return d;
  });
  await page.waitForTimeout(300); // queued IndexedDB writes
  await page.reload();
  await page.waitForFunction(() => window.ready === true);
  const id2 = await page.evaluate(() => window.t.openClient("persist"));
  assert.equal(id2, id);
  const json = await page.evaluate((d) => window.t.c.documentJson(d), doc);
  assert.deepEqual(JSON.parse(json), { a: 1, b: 2 });
  // objects() finds the document again without the app remembering its ID.
  const listed = await page.evaluate(() => window.t.c.objects("acme.todo"));
  assert.deepEqual(listed.map((o) => o.objectId), [doc]);
  assert.equal(listed[0].objectType, "acme.todo");
  assert.deepEqual(page.problems, []);
  await ctx.close();
});

// req: REQ-PLAT-006
await test("a second tab cannot open the same database; it can wait for the first", async () => {
  const ctx = await browser.newContext();
  const one = await newPage(ctx);
  const two = await newPage(ctx);
  const id = await one.evaluate(() => window.t.openClient("shared"));
  await one.evaluate(() => window.t.c.create("acme.note", new Uint8Array([1])));
  await one.waitForTimeout(300);
  const err = await two.evaluate(() => window.t.openClient("shared").then(() => null, (e) => String(e.message ?? e)));
  assert.match(err, /already open in another tab/);
  // Another database is not affected.
  await two.evaluate(() => window.t.openClient("other"));
  await two.evaluate(() => window.t.c.free());
  // Waiting: resolves when the first tab goes away, with the same data.
  const waiting = two.evaluate(() => window.t.openClient("shared", true));
  await two.waitForTimeout(500);
  await one.close();
  assert.equal(await waiting, id);
  assert.equal(await two.evaluate(() => window.t.c.historyLength !== undefined), true);
  await ctx.close();
});

// req: REQ-PLAT-008
await test("device key is stored encrypted and is stable", async () => {
  const ctx = await browser.newContext();
  const page = await newPage(ctx);
  const result = await page.evaluate(async () => {
    const { kith, web } = window.t;
    const a = await web.loadOrCreateDeviceKey("keytest", kith.generateSecretKey);
    const b = await web.loadOrCreateDeviceKey("keytest", kith.generateSecretKey);
    const same = a.length === 32 && a.every((x, i) => x === b[i]);
    // The stored record must not contain the secret in the clear and the wrapping key
    // must be non-extractable.
    const db = await new Promise((res, rej) => {
      const r = indexedDB.open("kith-keys:keytest");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const rec = await new Promise((res, rej) => {
      const r = db.transaction("keys").objectStore("keys").get("device");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    db.close();
    const ct = new Uint8Array(rec.ciphertext);
    const hex = (u) => Array.from(u, (x) => x.toString(16).padStart(2, "0")).join("");
    return {
      same,
      extractable: rec.wrapKey.extractable,
      plainInRecord: hex(ct).includes(hex(a)),
      persistent: typeof (await web.requestPersistentStorage()),
      estimate: await web.storageEstimate().then((e) => e === null || typeof e.quota === "number"),
    };
  });
  assert.equal(result.same, true);
  assert.equal(result.extractable, false);
  assert.equal(result.plainInRecord, false);
  assert.equal(result.persistent, "boolean");
  assert.equal(result.estimate, true);
  await ctx.close();
});

// req: REQ-PLAT-007, REQ-PLAT-003
await test("two browsers sync through the relay and reconnect after a relay restart", async () => {
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const a = await newPage(ctxA);
  const b = await newPage(ctxB);
  await a.evaluate(() => window.t.openClient("sync-a"));
  await b.evaluate(() => window.t.openClient("sync-b"));
  const org = await a.evaluate(() => window.t.c.createOrg());
  await a.evaluate(
    ([url, org]) => {
      const { c } = window.t;
      c.connect(url, org, (e) => {
        window.t.onEvent(e);
        if (e.type === "inviteClaimed") c.acceptClaim(e.from);
      });
    },
    [relayUrl, org],
  );
  await hasEvent(a, "connected");
  await hasEvent(a, "presence");
  const invite = await a.evaluate(([url, org]) => window.t.c.createInvite(org, url, 600), [relayUrl, org]);
  await b.evaluate(
    ([invite]) => {
      const { kith, c } = window.t;
      c.connect(kith.KithClient.parseInvite(invite).relay, kith.KithClient.parseInvite(invite).org, window.t.onEvent);
      window.t.code = c.claimInvite(invite);
    },
    [invite],
  );
  await hasEvent(b, "joined");

  // A live change reaches B.
  const obj = await a.evaluate(() => window.t.c.create("acme.note", new TextEncoder().encode("one")));
  await hasEvent(b, "received", { objectId: obj });
  assert.equal(await b.evaluate((o) => window.t.c.historyLength(o), obj), 1);

  // The relay goes away: both sides notice and start reconnecting.
  await stopRelay();
  await hasEvent(a, "reconnecting");
  await hasEvent(b, "reconnecting");
  // A edits while offline; the change is stored locally.
  await a.evaluate((o) => window.t.c.edit(o, new TextEncoder().encode("two")), obj);
  assert.equal(await a.evaluate((o) => window.t.c.historyLength(o), obj), 2);
  const mark = (page) => page.evaluate(() => window.t.events.length);
  const [markA, markB] = [await mark(a), await mark(b)];
  await startRelay();
  // Only events after the restart count: both come back, and each sees the other online.
  const afterRestart = (page, from, type, pred) =>
    page.waitForFunction(
      ([from, type, n]) => window.t.events.slice(from).some((e) => e.type === type && (n === undefined || e.online?.length === n)),
      [from, type, pred],
      { timeout: 40000 },
    );
  await afterRestart(a, markA, "connected");
  await afterRestart(b, markB, "connected");
  await afterRestart(b, markB, "presence", 2);
  // After reconnecting, catch-up exchanges what was missed.
  await b.evaluate(() => window.t.c.catchUp());
  await b.waitForFunction((o) => window.t.c.historyLength(o) === 2, obj, { timeout: 20000 });
  assert.deepEqual(a.problems.filter((p) => !/WebSocket|ERR_CONNECTION/.test(p)), []);
  await ctxA.close();
  await ctxB.close();
});

// Size and load measurements, for the numbers in docs/guides/web-production.md.
//   KITH_MEASURE=10000,50000 node run.mjs   (number of changes to write per run)
if (process.env.KITH_MEASURE) {
  for (const n of process.env.KITH_MEASURE.split(",").map(Number)) {
    const ctx = await browser.newContext();
    const page = await newPage(ctx);
    const db = `measure-${n}`;
    await page.evaluate((db) => window.t.openClient(db), db);
    const { write, last } = await page.evaluate((n) => {
      const t0 = performance.now();
      const payload = new Uint8Array(200).fill(7);
      let last;
      for (let i = 0; i < n; i++) last = window.t.c.create("acme.note", payload);
      return { write: performance.now() - t0, last };
    }, n);
    // Wait until every change is committed to IndexedDB.
    await page.waitForFunction(
      ([db, n]) =>
        new Promise((resolve) => {
          const r = indexedDB.open(db);
          r.onsuccess = () => {
            const q = r.result.transaction("changes").objectStore("changes").count();
            q.onsuccess = () => {
              r.result.close();
              resolve(q.result >= n);
            };
          };
        }),
      [db, n],
      { timeout: 120000, polling: 1000 },
    );
    const afterWrite = await page.evaluate(() => window.t.wasm.memory.buffer.byteLength);
    await page.reload();
    await page.waitForFunction(() => window.ready === true);
    const open = await page.evaluate(async ([db, last]) => {
      const t0 = performance.now();
      await window.t.openClient(db);
      const ms = performance.now() - t0;
      if (window.t.c.historyLength(last) !== 1) throw new Error("data was not loaded");
      return ms;
    }, [db, last]);
    const mem = await page.evaluate(() => window.t.wasm.memory.buffer.byteLength);
    const est = await page.evaluate(() => window.t.web.storageEstimate());
    console.log(
      `measure n=${n}: create ${Math.round(write)} ms (${Math.round((write / n) * 1000)} us each), ` +
        `open from IndexedDB ${Math.round(open)} ms, wasm memory ${(mem / 1048576).toFixed(0)} MiB ` +
        `(${(afterWrite / 1048576).toFixed(0)} MiB when writing), storage ${est ? (est.usage / 1048576).toFixed(0) : "?"} MiB`,
    );
    await ctx.close();
  }
  const files = ["kith_bg.wasm", "kith.js"];
  const { gzipSync } = await import("node:zlib");
  for (const f of files) {
    const b = readFileSync(join(pkg, f));
    console.log(`size ${f}: ${(b.length / 1048576).toFixed(2)} MiB, gzip ${(gzipSync(b).length / 1048576).toFixed(2)} MiB`);
  }
}

await browser.close();
server.close();
relay.kill();
if (failures.length) {
  console.log(`\n${failures.length} failed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nall browser tests passed");
process.exit(0);
