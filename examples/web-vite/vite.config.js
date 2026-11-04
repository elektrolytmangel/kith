import { defineConfig } from "vite";

export default defineConfig({
  // The package loads its .wasm with `new URL(..., import.meta.url)`, which Vite handles
  // as an asset. Keep it out of dependency pre-bundling so that URL stays intact.
  optimizeDeps: { exclude: ["@elektrolytmangel/kith-wasm"] },
  build: { target: "es2022" },
});
