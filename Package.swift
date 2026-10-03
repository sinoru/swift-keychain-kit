// swift-tools-version: 6.4
//
//  Package.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import PackageDescription

let commonSwiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("ApproachableConcurrency"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("ImmutableWeakCaptures"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .strictMemorySafety(),
    // This is a library, so nothing here should inherit MainActor isolation by default.
    .defaultIsolation(nil),
]

let package = Package(
    name: "KeychainKit",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
        .watchOS(.v10),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "KeychainKit",
            targets: ["KeychainKit"]
        ),
    ],
    dependencies: [
        // Synchronizes the in-memory backend in the test-support target. The library itself has no dependencies.
        .package(
            url: "https://github.com/sinoru/swift-synchronization-kit.git",
            from: "1.1.2",
            traits: ["Mutex"]
        ),
    ],
    targets: [
        .target(
            name: "KeychainKit",
            swiftSettings: commonSwiftSettings,
        ),
        // In-memory backend and temporary-keychain fixtures. Not part of any product.
        .target(
            name: "KeychainKitTestSupport",
            dependencies: [
                "KeychainKit",
                .product(name: "SynchronizationKit", package: "swift-synchronization-kit"),
            ],
            swiftSettings: commonSwiftSettings,
        ),
        .testTarget(
            name: "KeychainKitTests",
            dependencies: ["KeychainKit", "KeychainKitTestSupport"],
            swiftSettings: commonSwiftSettings,
        ),
    ]
)
