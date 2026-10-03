// swift-tools-version: 6.2
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
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "KeychainKit",
            targets: ["KeychainKit"]
        ),
    ],
    targets: [
        .target(
            name: "KeychainKit",
            swiftSettings: commonSwiftSettings,
        ),
        // Temporary-keychain fixtures for the integration tests. Not part of any product.
        .target(
            name: "KeychainKitTestSupport",
            dependencies: ["KeychainKit"],
            swiftSettings: commonSwiftSettings,
        ),
        .testTarget(
            name: "KeychainKitTests",
            dependencies: ["KeychainKit", "KeychainKitTestSupport"],
            swiftSettings: commonSwiftSettings,
        ),
    ]
)
