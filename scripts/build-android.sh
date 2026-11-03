#!/usr/bin/env bash
# Build Android native libs + Kotlin sources into bindings/kotlin/kith.
# Requires ANDROID_NDK_HOME and `cargo install cargo-ndk`.
set -euo pipefail
cd "$(dirname "$0")/.."
ABIS=(arm64-v8a armeabi-v7a x86_64)
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
OUT=bindings/kotlin/kith/src/main
cargo ndk $(printf -- '-t %s ' "${ABIS[@]}") -o "$OUT/jniLibs" build -p kith-ffi --release
# Kotlin sources come from an unstripped host build: the release profile strips
# the shipped .so files, which removes the UniFFI metadata bindgen reads.
# The metadata is the same for every target.
cargo build -p kith-ffi
for HOST_LIB in target/debug/libkith_ffi.so target/debug/libkith_ffi.dylib; do
  [ -f "$HOST_LIB" ] && break
done
scripts/gen-bindings.sh kotlin "$HOST_LIB" "$OUT/kotlin"
echo "now run: (cd bindings/kotlin && ./gradlew assembleRelease)"
