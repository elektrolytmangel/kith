#!/usr/bin/env bash
# Generate Swift/Kotlin sources from a compiled kith-ffi library (UniFFI library mode).
#   scripts/gen-bindings.sh <swift|kotlin> <path/to/libkith_ffi.{so,dylib,a}> <out-dir>
set -euo pipefail
cd "$(dirname "$0")/.."
LANG_="$1"; LIB="$2"; OUT="$3"
mkdir -p "$OUT"
cargo run -q -p kith-ffi --features cli --bin uniffi-bindgen -- \
  generate --library "$LIB" --language "$LANG_" --out-dir "$OUT"
