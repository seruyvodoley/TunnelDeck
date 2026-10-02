// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TunnelDeck",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "TunnelDeck", targets: ["TunnelDeck"])],
    targets: [
        .executableTarget(name: "TunnelDeck", exclude: ["Resources/Info.plist"]),
        .testTarget(name: "TunnelDeckTests", dependencies: ["TunnelDeck"])
    ]
)
