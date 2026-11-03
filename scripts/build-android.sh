#!/usr/bin/env bash
# Build Android native libs + Kotlin sources into bindings/kotlin/kith.
# Requires ANDROID_NDK_HOME and `cargo install cargo-ndk`.
set -euo pipefail
cd "$(dirname "$0")/.."
ABIS=(arm64-v8a armeabi-v7a x86_64)
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
OUT=bindings/kotlin/kith/src/main
cargo ndk $(printf -- '-t %s ' "${ABIS[@]}") -o "$OUT/jniLibs" build -p kith-ffi --release
scripts/gen-bindings.sh kotlin target/aarch64-linux-android/release/libkith_ffi.so "$OUT/kotlin"
echo "now run: (cd bindings/kotlin && gradle assembleRelease)"
