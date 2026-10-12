// swift-tools-version:5.9
// The Recipes target holds one file per recipe; copy the file you need. The harness replays the vectors.
import PackageDescription

let package = Package(
    name: "crypto-recipes",
    platforms: [.macOS(.v13), .iOS(.v16)],
    targets: [
        .target(name: "Recipes"),
        .executableTarget(name: "harness", dependencies: ["Recipes"]),
    ]
)
