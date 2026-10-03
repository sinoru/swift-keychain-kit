//
//  Keychain.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The entry point to Keychain Services.
///
/// It holds only immutable configuration, so it is `Sendable` and can be shared across
/// isolation domains as is. The operations (add, first, all, update, delete) arrive in Phase 3.
public struct Keychain: Sendable {
    public init() {}
}
