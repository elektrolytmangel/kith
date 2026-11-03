// swift-tools-version:5.9
// Local development manifest: uses the xcframework built by scripts/build-swift.sh.
// Releases publish a manifest pointing at the release asset (see .github/workflows/release.yml).
import PackageDescription

let package = Package(
    name: "Kith",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "Kith", targets: ["Kith"]),
    ],
    targets: [
        .binaryTarget(name: "KithFFI", path: "KithFFI.xcframework"),
        .target(name: "Kith", dependencies: ["KithFFI"], path: "Sources/Kith"),
        .testTarget(name: "KithTests", dependencies: ["Kith"], path: "Tests/KithTests"),
    ]
)
