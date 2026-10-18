// swift-tools-version: 6.0
// Security-audit harness. Lives outside the app's own package on purpose: it links
// the real KdbxCore/FleenKit but adds nothing to the shipping targets.
import PackageDescription

let package = Package(
    name: "FleenAudit",
    platforms: [.macOS(.v14)],
    dependencies: [.package(name: "Fleen", path: "../..")],
    targets: [
        .executableTarget(
            name: "fleen-audit",
            dependencies: [
                .product(name: "KdbxCore", package: "Fleen"),
                .product(name: "FleenKit", package: "Fleen"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)
