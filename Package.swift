// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TunnelDeck",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "TunnelDeck", targets: ["TunnelDeck"])],
    targets: [
        .systemLibrary(name: "CSQLite", path: "Sources/CSQLite"),
        .systemLibrary(name: "CCommonCrypto", path: "Sources/CCommonCrypto"),
        .executableTarget(name: "TunnelDeck", dependencies: ["CSQLite", "CCommonCrypto"], exclude: ["Resources/Info.plist"]),
        .testTarget(name: "TunnelDeckTests", dependencies: ["TunnelDeck"])
    ]
)
