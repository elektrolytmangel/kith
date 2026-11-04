#!/usr/bin/env bash
# Build the npm package from bindings/wasm into bindings/wasm/pkg.
#   NPM_SCOPE=myorg scripts/build-wasm.sh [web|bundler|nodejs]
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET="${1:-web}"
SCOPE="${NPM_SCOPE:-elektrolytmangel}"  # same default as release.yml (repository owner)
command -v wasm-pack >/dev/null || { echo "install wasm-pack: https://rustwasm.github.io/wasm-pack/installer/"; exit 1; }
wasm-pack build bindings/wasm --release --target "$TARGET" --scope "$SCOPE" --out-name kith
# Hand-written browser helpers ship in the same package (import ".../kith-web.js").
cp bindings/wasm/js/kith-web.js bindings/wasm/js/kith-web.d.ts bindings/wasm/pkg/
jq '.files += ["kith-web.js", "kith-web.d.ts"]' bindings/wasm/pkg/package.json > bindings/wasm/pkg/package.json.tmp
mv bindings/wasm/pkg/package.json.tmp bindings/wasm/pkg/package.json
# Package name becomes @<scope>/kith-wasm; version comes from Cargo.toml.
echo "built bindings/wasm/pkg ($(jq -r '.name + "@" + .version' bindings/wasm/pkg/package.json 2>/dev/null || echo ok))"
