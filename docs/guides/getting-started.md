# Getting started

A walk from nothing to two browsers editing the same notes through a relay. About 20 minutes.
**Web is the supported platform** for production. Swift and Kotlin are non-production
previews ([below](#other-platforms)).

You need Node 22+ (or a browser) and Docker or a relay binary from the
[release](https://github.com/elektrolytmangel/kith/releases).

## 1. Run a relay

The relay routes encrypted messages between devices and stores nothing. For development:

```sh
docker run --rm -p 8080:8080 ghcr.io/elektrolytmangel/kith-relay:0.1.0-alpha.4
curl localhost:8080/healthz          # ok
```

Clients connect to `ws://localhost:8080/v1/ws`. Anything beyond your own machine needs TLS
(`wss://`) in front of it: see [Deployment](deployment.md).

## 2. Install the package

```sh
npm install https://github.com/elektrolytmangel/kith/releases/download/v0.1.0-alpha.4/kith-wasm-0.1.0-alpha.4.tgz
```

The quickest way to see everything working is the example app
([`examples/web-vite`](../../examples/web-vite)): build the package from a checkout with
`scripts/build-wasm.sh web`, then `npm install && npm run dev` in the example and open it in two
browser profiles. The rest of this page builds the same thing step by step.

## 3. The first device

```ts
import init, { KithClient, generateSecretKey } from "@elektrolytmangel/kith-wasm";
import { loadOrCreateDeviceKey, requestPersistentStorage } from "@elektrolytmangel/kith-wasm/kith-web.js";

await init();
const key = await loadOrCreateDeviceKey("my-app", generateSecretKey); // kept encrypted in IndexedDB
const client = await KithClient.open("my-app", key);                  // data lives in IndexedDB too
requestPersistentStorage();

const org = client.createOrg();   // first device only: you are the admin; keep `org` (not secret)
const relay = "ws://localhost:8080/v1/ws";
client.connect(relay, org, (e) => {
  if (e.type === "received" || e.type === "syncReceived") render();
});

const id = client.createDocument("my.note", JSON.stringify({ text: "hello" }));
client.updateDocument(id, JSON.stringify({ text: "hello world" })); // a merge patch
```

Documents merge: two devices editing different keys of the same document both keep their edit.
`client.objects("my.note")` lists what the device knows; `client.documentJson(id)` reads one.
Everything is signed by the device and encrypted before it leaves the browser.

## 4. A second device

On the first device create an invite (single use, expires):

```ts
const link = client.createInvite(org, relay, 24 * 3600);
```

Hand the link to the other device (QR code, message). On the second device:

```ts
const { org, relay } = KithClient.parseInvite(link);
client.connect(relay, org, onEvent);
client.claimInvite(link);
```

Both screens now show a 6-digit code (events `claimCode` on the new device and
`inviteClaimed` on the admin's). **The people compare the codes.** If they match, the admin
calls `client.acceptClaim(e.from)`; the new device gets a `joined` event. This check is what
stops someone who got hold of the link from joining unseen.

## 5. Offline and catching up

Changes are always written locally first. A device that was offline receives only what
arrives while it is online, so after (re)connecting call `catchUp()` once a `presence` event
shows another device:

```ts
case "presence": if (e.online.length > 1) client.catchUp(); break;
```

The two compare what they have and exchange the difference (large histories in batches,
and an interrupted catch-up continues next time). If no other member is ever online at the
same time, nothing syncs: run the [always-on client](integration.md#always-on-client).

## 6. Roles and removal

`client.grantAdmin(device)`, `client.setRole(device, role)` and `client.removeMember(device)`
(admins only); see [Roles and write permissions](integration.md#roles-and-write-permissions).
A removed device cannot read anything sent afterwards, but keeps what it received earlier
([threat model](threat-model.md)).

## Before you ship

- [ ] **Know the limits** in the [threat model](threat-model.md): alpha software, no
      independent audit yet, formats may still break between alphas.
- [ ] **TLS and an approved-orgs list** on your relay ([Deployment](deployment.md),
      [Azure](deployment-azure.md)).
- [ ] **One tab per database, CSP, persistent storage, size**: [Web apps in production](web-production.md).
- [ ] **No compaction yet:** history is kept forever and held in memory (about 0.75 KiB per
      change). Plan for a few ten thousand changes per device and prefer documents over one
      object per keystroke.
- [ ] **Backups** (`exportBackup(passphrase)`) and an **always-on client** so data survives
      a lost device.
- [ ] **Upgrades:** alphas can break stored data and the protocol; read the changelog's
      *Upgrading* section before every update. A compatibility promise starts with the first beta
      ([ADR 0012](../adr/0012-format-stability.md)).

## Other platforms

> **Non-production.** The Swift package and the Android library are built and tested in CI, but
> their live-sync code has never run on real devices. Use them to try things out, not to ship.

| Platform | Install | Guide |
| --- | --- | --- |
| iOS / macOS (Swift) | `kith-swift-package.zip` from the release, added as a local package | [Integration: iOS / macOS](integration.md#ios--macos) |
| Android (Kotlin) | `kith-android-<version>.aar` from the release | [Integration: Android](integration.md#android) |
| Rust (desktop, Tauri, servers) | git dependency on a release tag | [Integration: Rust](integration.md#rust-desktop-tauri-headless) |

The API is the same everywhere (`create`, `createDocument`, `connect`, `createInvite`, …), so the
steps above carry over; Swift and Kotlin hand the WebSocket to your app (`RelaySession`).
