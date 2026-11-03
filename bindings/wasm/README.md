# @kith/kith-wasm

kith for the web, Electron and Node, compiled to WebAssembly.

```ts
import init, { KithClient, version } from "@kith/kith-wasm";

await init();
const client = new KithClient();
const objectId = client.create("note", new TextEncoder().encode("hello"));
console.log(version(), client.deviceId(), client.historyLength(objectId));
```

Build locally: `scripts/build-wasm.sh web` (output in `bindings/wasm/pkg`).
