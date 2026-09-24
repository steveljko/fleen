// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Fleen",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "KdbxCore", targets: ["KdbxCore"]),
        .library(name: "FleenKit", targets: ["FleenKit"]),
        .executable(name: "fleen-cli", targets: ["fleen-cli"]),
        .executable(name: "Fleen", targets: ["Fleen"])
    ],
    targets: [
        // Vendored reference Argon2 (phc-winner-argon2 20190702, CC0/Apache-2.0).
        // Hand-rolling Argon2 would be reckless; this is the PHC reference code,
        // unmodified, with the portable `ref.c` core (no x86 SIMD assumptions).
        .target(
            name: "CArgon2",
            exclude: ["LICENSE"],
            cSettings: [
                .headerSearchPath(".")
                // Deliberately NO `-DARGON2_NO_THREADS`: defining it forces the
                // single-threaded path, so a database asking for 2 lanes derives its
                // key on one core and unlocking takes twice as long as it should.
                // (An earlier `.when(platforms: [])` here was meant as a no-op and is
                // in fact applied unconditionally — it silently halved unlock speed.)
            ]
        ),
        .target(
            name: "KdbxCore",
            dependencies: ["CArgon2"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // App-layer logic with no UI dependency, so it can be unit tested without
        // dragging in AppKit.
        .target(
            name: "FleenKit",
            dependencies: ["KdbxCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // The menu bar app. Built into a real .app bundle by Scripts/build-app.sh —
        // SwiftPM alone produces a bare executable, which cannot own a status item
        // or be code-signed with entitlements.
        .executableTarget(
            name: "Fleen",
            dependencies: ["FleenKit", "KdbxCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // A thin harness for exercising the engine against a real database by hand.
        // Not the shipping app — that is the Phase 2 menu bar target.
        .executableTarget(
            name: "fleen-cli",
            dependencies: ["KdbxCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "FleenKitTests",
            dependencies: ["FleenKit"],
            // Shares the engine's fixtures: the recycle bin tests need a real
            // database whose bin was populated by another implementation.
            resources: [.copy("Fixtures")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "KdbxCoreTests",
            dependencies: ["KdbxCore"],
            resources: [.copy("Fixtures")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
