// swift-tools-version:5.10
import PackageDescription

var targets: [Target] = [
    .target(name: "HeimdallCore", path: "Sources/HeimdallCore"),
    .executableTarget(name: "heimdall-scan", dependencies: ["HeimdallCore"], path: "Sources/heimdall-scan"),
    .testTarget(name: "HeimdallCoreTests", dependencies: ["HeimdallCore"], path: "Tests/HeimdallCoreTests"),
]
#if os(macOS)
targets.append(.executableTarget(name: "Heimdall", dependencies: ["HeimdallCore"], path: "Sources/Heimdall"))
#endif

let package = Package(
    name: "Heimdall",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "HeimdallCore", targets: ["HeimdallCore"]),
        .executable(name: "heimdall-scan", targets: ["heimdall-scan"]),
    ],
    targets: targets
)
