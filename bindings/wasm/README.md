# @elektrolytmangel/kith-wasm

kith for the web, Electron and Node, compiled to WebAssembly.

```ts
import init, { KithClient, version } from "@elektrolytmangel/kith-wasm";

await init();
const client = new KithClient();
const objectId = client.create("note", new TextEncoder().encode("hello"));
console.log(version(), client.deviceId(), client.historyLength(objectId));
```

Install from a release: `npm install https://github.com/elektrolytmangel/kith/releases/download/vX.Y.Z/kith-wasm-X.Y.Z.tgz`.

Build locally: `scripts/build-wasm.sh web` (output in `bindings/wasm/pkg`).
