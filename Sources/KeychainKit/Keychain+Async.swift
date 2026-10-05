//
//  Keychain+Async.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

/// Asynchronous forms of every operation.
///
/// Security's functions block the calling thread on IPC to `securityd`, and under
/// `NonisolatedNonsendingByDefault` a plain `async` function would do that blocking on the
/// caller's actor. `@concurrent` moves each call to the global concurrent executor instead.
/// The work itself is not cancellable: a call in flight runs to completion.
///
/// In an asynchronous context the compiler always picks these overloads (SE-0296), so each
/// body reaches the synchronous implementation through a function reference with an explicit
/// synchronous type.
extension Keychain {
    /// The asynchronous form of ``add(_:authenticationContext:)``.
    @discardableResult
    @concurrent
    public func add<Class>(
        _ item: Item<Class>,
        authenticationContext: AuthenticationContext? = nil,
    ) async throws(KeychainError) -> PersistentReference {
        let synchronous: (Item<Class>, AuthenticationContext?) throws(KeychainError) -> PersistentReference = add(_:authenticationContext:)
        return try synchronous(item, authenticationContext)
    }

    /// The asynchronous form of ``fetchFirst(matching:authenticationContext:skippingItemsRequiringAuthentication:)`` for the password classes.
    @concurrent
    public func fetchFirst<Class: PasswordItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Item<Class>? {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> Item<Class>? = fetchFirst(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirst(matching:authenticationContext:skippingItemsRequiringAuthentication:)`` for keys, certificates, and identities.
    @concurrent
    public func fetchFirst<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Item<Class>? {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> Item<Class>? = fetchFirst(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstAttributes(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstAttributes<Class>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Attributes<Class>? {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> Attributes<Class>? = fetchFirstAttributes(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstData(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstData<Class: PasswordItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Data? {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> Data? = fetchFirstData(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstReference(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstReference<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Class.Reference? {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> Class.Reference? = fetchFirstReference(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstPersistentReference(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstPersistentReference<Class>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> PersistentReference? {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> PersistentReference? = fetchFirstPersistentReference(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetch(matching:authenticationContext:skippingItemsRequiringAuthentication:)`` for the password classes.
    @concurrent
    public func fetch<Class: PasswordItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Item<Class>] {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> [Item<Class>] = fetch(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetch(matching:authenticationContext:skippingItemsRequiringAuthentication:)`` for keys, certificates, and identities.
    @concurrent
    public func fetch<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Item<Class>] {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> [Item<Class>] = fetch(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchAttributes(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchAttributes<Class>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Attributes<Class>] {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> [Attributes<Class>] = fetchAttributes(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchReferences(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchReferences<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Class.Reference] {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> [Class.Reference] = fetchReferences(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchPersistentReferences(matching:authenticationContext:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchPersistentReferences<Class>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [PersistentReference] {
        let synchronous: (Query<Class>, AuthenticationContext?, Bool) throws(KeychainError) -> [PersistentReference] = fetchPersistentReferences(matching:authenticationContext:skippingItemsRequiringAuthentication:)
        return try synchronous(query, authenticationContext, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``generateKey(_:sizeInBits:attributes:authenticationContext:)``.
    @concurrent
    public func generateKey(
        _ keyType: KeyType,
        sizeInBits: Int,
        attributes: Attributes<CryptographicKey> = Attributes(),
        authenticationContext: AuthenticationContext? = nil,
    ) async throws(KeychainError) -> KeyReference {
        let synchronous: (KeyType, Int, Attributes<CryptographicKey>, AuthenticationContext?) throws(KeychainError) -> KeyReference = generateKey(_:sizeInBits:attributes:authenticationContext:)
        return try synchronous(keyType, sizeInBits, attributes, authenticationContext)
    }

    /// The asynchronous form of ``generateSecureEnclaveKey(applicationTag:label:accessGroup:accessibility:constraints:authenticationContext:)``.
    @concurrent
    public func generateSecureEnclaveKey(
        applicationTag: Data? = nil,
        label: String? = nil,
        accessGroup: AccessGroup? = nil,
        accessibility: Accessibility = .whenUnlockedThisDeviceOnly,
        constraints: AccessControl.Flags = [],
        authenticationContext: AuthenticationContext? = nil,
    ) async throws(KeychainError) -> KeyReference {
        let synchronous: (Data?, String?, AccessGroup?, Accessibility, AccessControl.Flags, AuthenticationContext?) throws(KeychainError) -> KeyReference = generateSecureEnclaveKey(applicationTag:label:accessGroup:accessibility:constraints:authenticationContext:)
        return try synchronous(applicationTag, label, accessGroup, accessibility, constraints, authenticationContext)
    }

    /// The asynchronous form of ``update(matching:with:authenticationContext:)``.
    @concurrent
    public func update<Class>(
        matching query: Query<Class>,
        with changes: Item<Class>,
        authenticationContext: AuthenticationContext? = nil,
    ) async throws(KeychainError) {
        let synchronous: (Query<Class>, Item<Class>, AuthenticationContext?) throws(KeychainError) -> Void = update(matching:with:authenticationContext:)
        try synchronous(query, changes, authenticationContext)
    }

    /// The asynchronous form of ``delete(matching:authenticationContext:)``.
    @concurrent
    public func delete<Class>(
        matching query: Query<Class>,
        authenticationContext: AuthenticationContext? = nil,
    ) async throws(KeychainError) {
        let synchronous: (Query<Class>, AuthenticationContext?) throws(KeychainError) -> Void = delete(matching:authenticationContext:)
        try synchronous(query, authenticationContext)
    }
}
