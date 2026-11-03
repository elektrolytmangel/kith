#!/usr/bin/env bash
# Build KithFFI.xcframework (iOS device, iOS simulator, macOS) and Swift sources.
# Requires macOS with Xcode. Output: bindings/swift/KithFFI.xcframework(.zip)
set -euo pipefail
cd "$(dirname "$0")/.."
CRATE=kith-ffi
LIB=libkith_ffi.a
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin)

rustup target add "${TARGETS[@]}"
for t in "${TARGETS[@]}"; do
  cargo build -p "$CRATE" --release --target "$t"
done

WORK=target/swift; rm -rf "$WORK"; mkdir -p "$WORK"/{headers,ios-sim,macos}
scripts/gen-bindings.sh swift target/aarch64-apple-darwin/release/$LIB "$WORK/gen"

cp "$WORK"/gen/*.h "$WORK/headers/"
cat "$WORK"/gen/*.modulemap > "$WORK/headers/module.modulemap"
mkdir -p bindings/swift/Sources/Kith
cp "$WORK"/gen/*.swift bindings/swift/Sources/Kith/

lipo -create target/aarch64-apple-ios-sim/release/$LIB target/x86_64-apple-ios/release/$LIB -output "$WORK/ios-sim/$LIB"
lipo -create target/aarch64-apple-darwin/release/$LIB target/x86_64-apple-darwin/release/$LIB -output "$WORK/macos/$LIB"

rm -rf bindings/swift/KithFFI.xcframework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/$LIB -headers "$WORK/headers" \
  -library "$WORK/ios-sim/$LIB" -headers "$WORK/headers" \
  -library "$WORK/macos/$LIB" -headers "$WORK/headers" \
  -output bindings/swift/KithFFI.xcframework

(cd bindings/swift && rm -f KithFFI.xcframework.zip && zip -qry KithFFI.xcframework.zip KithFFI.xcframework)
swift package compute-checksum bindings/swift/KithFFI.xcframework.zip > bindings/swift/KithFFI.xcframework.zip.sha256
echo "checksum: $(cat bindings/swift/KithFFI.xcframework.zip.sha256)"
