//
//  Keychain.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The entry point to Keychain Services.
///
/// A `Keychain` holds only configuration, so it is `Sendable` and can be shared across
/// isolation domains as is. Each call goes straight to the Security framework; the framework's
/// functions are thread-safe, and any serialization the caller needs for user-facing prompts
/// is the caller's to arrange.
public struct Keychain: Sendable {
    /// Which keychain implementation the calls target.
    public var storage: Storage

    /// The access group applied to every operation that does not name one itself.
    ///
    /// `nil` leaves the choice to the framework, which uses the app's default group for adds
    /// and searches every group the app belongs to.
    public var accessGroup: AccessGroup?

    let backend: any KeychainBackend

    public init(storage: Storage = .dataProtection, accessGroup: AccessGroup? = nil) {
        self.init(backend: SecurityBackend(), storage: storage, accessGroup: accessGroup)
    }

    package init(backend: any KeychainBackend, storage: Storage, accessGroup: AccessGroup?) {
        self.backend = backend
        self.storage = storage
        self.accessGroup = accessGroup
    }
}
