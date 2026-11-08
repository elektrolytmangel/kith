// A tiny notes app. Shows the parts every web app needs:
//  - one device key, kept encrypted at rest (loadOrCreateDeviceKey)
//  - one owner per database: a second tab says so instead of corrupting state
//  - documents that merge between devices, listed with objects()
//  - relay connection that reconnects by itself; catch up after (re)connecting
import init, { KithClient, generateSecretKey } from "@elektrolytmangel/kith-wasm";
import { loadOrCreateDeviceKey, requestPersistentStorage } from "@elektrolytmangel/kith-wasm/kith-web.js";

const $ = (id) => document.getElementById(id);
const status = (text) => ($("status").textContent = text);
const DB = "kith-notes";
const ORG_KEY = "kith-notes-org"; // not secret; the app remembers which org it belongs to

await init();

let client;
try {
  const key = await loadOrCreateDeviceKey(DB, generateSecretKey);
  client = await KithClient.open(DB, key);
} catch (e) {
  if (/already open in another tab/.test(e.message)) {
    status("This app is open in another tab. Close it there, or reload when it is closed.");
    // Alternative: KithClient.open(DB, key, true) waits until the other tab is gone.
    throw e;
  }
  throw e;
}
requestPersistentStorage(); // ask the browser not to evict our data

function render() {
  // objects() lists everything this device knows, also after a restart or a catch-up.
  $("notes").replaceChildren(
    ...client.objects("example.note").map((o) => {
      const li = document.createElement("li");
      li.textContent = JSON.parse(client.documentJson(o.objectId)).text;
      return li;
    }),
  );
}

$("add").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const text = $("text").value.trim();
  if (!text) return;
  client.createDocument("example.note", JSON.stringify({ text }));
  $("text").value = "";
  render();
});

const onEvent = (e) => {
  switch (e.type) {
    case "connected": status("connected"); break;
    case "reconnecting": status(`offline, retrying in ${Math.round(e.delayMs / 1000)} s (attempt ${e.attempt})`); break;
    case "received":
    case "syncReceived": render(); break;
    case "inviteClaimed": $("code").textContent = `code ${e.code}: compare, then accepted`; client.acceptClaim(e.from); break;
    case "claimCode": $("code").textContent = `code ${e.code}: compare it with the other device`; break;
    case "joined": status("joined the group"); $("invite").disabled = false; break;
  }
};

const org0 = localStorage.getItem(ORG_KEY);
if (org0 && client.isMember(org0)) {
  client.connect($("relay").value, org0, onEvent);
  $("invite").disabled = false;
}
$("start").onclick = () => {
  const org = org0 ?? client.createOrg();
  localStorage.setItem(ORG_KEY, org);
  client.connect($("relay").value, org, onEvent);
  $("invite").disabled = false;
};
$("invite").onclick = () => {
  $("link").textContent = client.createInvite(localStorage.getItem(ORG_KEY), $("relay").value, 24 * 3600);
};
$("join").onclick = () => {
  const link = $("joinlink").value.trim();
  const { org, relay } = KithClient.parseInvite(link);
  localStorage.setItem(ORG_KEY, org);
  client.connect(relay, org, onEvent);
  client.claimInvite(link);
  $("code").textContent = "claimed: waiting for the other device's answer";
};

status("ready");
render();
