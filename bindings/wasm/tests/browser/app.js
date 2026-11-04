// Loaded by the test page. The page's Content-Security-Policy allows no
// 'unsafe-eval' and no inline scripts, so this also proves the package runs under it.
import init, * as kith from "/pkg/kith.js";
import * as web from "/pkg/kith-web.js";

const wasm = await init();

const t = { kith, web, wasm, c: null, events: [] };
t.openClient = async (db, wait) => {
  const key = await web.loadOrCreateDeviceKey(db, kith.generateSecretKey);
  t.c = await kith.KithClient.open(db, key, wait);
  return t.c.deviceId();
};
t.onEvent = (e) => t.events.push(e);
window.t = t;
window.ready = true;
