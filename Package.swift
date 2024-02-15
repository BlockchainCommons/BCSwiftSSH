// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "BCSSH",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "BCSSH",
            targets: ["BCSSH"]),
    ],
    dependencies: [
        .package(url: "https://github.com/BlockchainCommons/BCSwiftCrypto", from: "1.2.0"),
        .package(url: "https://github.com/WolfMcNally/WolfBase", from: "6.0.0"),
    ],
    targets: [
        .target(
            name: "BCSSH",
            dependencies: [
                "WolfBase",
                .product(name: "BCCrypto", package: "BCSwiftCrypto"),
            ]
        ),
        .testTarget(
            name: "BCSSHTests",
            dependencies: [
                "BCSSH",
                "WolfBase"
            ]),
    ]
)
