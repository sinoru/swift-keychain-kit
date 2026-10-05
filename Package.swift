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
    dependencies: [
        .package(
            url: "https://github.com/sinoru/swift-core-foundation-kit.git",
            from: "0.1.0"
        ),
    ],
    targets: [
        .target(
            name: "KeychainKit",
            dependencies: [
                .product(name: "CoreFoundationKit", package: "swift-core-foundation-kit"),
            ],
            swiftSettings: commonSwiftSettings,
        ),
        .testTarget(
            name: "KeychainKitTests",
            dependencies: ["KeychainKit"],
            swiftSettings: commonSwiftSettings,
        ),
    ]
)
