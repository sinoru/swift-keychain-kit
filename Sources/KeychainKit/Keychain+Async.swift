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
    #if canImport(LocalAuthentication) && !os(tvOS)
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
    #else
    /// The asynchronous form of ``add(_:)``.
    @discardableResult
    @concurrent
    public func add<Class>(_ item: Item<Class>) async throws(KeychainError) -> PersistentReference {
        let synchronous: (Item<Class>) throws(KeychainError) -> PersistentReference = add(_:)
        return try synchronous(item)
    }
    #endif

    /// The asynchronous form of ``fetchFirst(matching:skippingItemsRequiringAuthentication:)`` for the password classes.
    @concurrent
    public func fetchFirst<Class: PasswordItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Item<Class>? {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> Item<Class>? = fetchFirst(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirst(matching:skippingItemsRequiringAuthentication:)`` for keys, certificates, and identities.
    @concurrent
    public func fetchFirst<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Item<Class>? {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> Item<Class>? = fetchFirst(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstAttributes(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstAttributes<Class>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Attributes<Class>? {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> Attributes<Class>? = fetchFirstAttributes(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstData(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstData<Class: PasswordItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Data? {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> Data? = fetchFirstData(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstReference(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstReference<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> Class.Reference? {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> Class.Reference? = fetchFirstReference(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchFirstPersistentReference(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchFirstPersistentReference<Class>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> PersistentReference? {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> PersistentReference? = fetchFirstPersistentReference(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetch(matching:skippingItemsRequiringAuthentication:)`` for the password classes.
    @concurrent
    public func fetch<Class: PasswordItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Item<Class>] {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> [Item<Class>] = fetch(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetch(matching:skippingItemsRequiringAuthentication:)`` for keys, certificates, and identities.
    @concurrent
    public func fetch<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Item<Class>] {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> [Item<Class>] = fetch(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchAttributes(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchAttributes<Class>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Attributes<Class>] {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> [Attributes<Class>] = fetchAttributes(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchReferences(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchReferences<Class: ReferenceItemClass>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [Class.Reference] {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> [Class.Reference] = fetchReferences(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    /// The asynchronous form of ``fetchPersistentReferences(matching:skippingItemsRequiringAuthentication:)``.
    @concurrent
    public func fetchPersistentReferences<Class>(
        matching query: Query<Class>,
        skippingItemsRequiringAuthentication: Bool = false,
    ) async throws(KeychainError) -> [PersistentReference] {
        let synchronous: (Query<Class>, Bool) throws(KeychainError) -> [PersistentReference] = fetchPersistentReferences(matching:skippingItemsRequiringAuthentication:)
        return try synchronous(query, skippingItemsRequiringAuthentication)
    }

    #if canImport(LocalAuthentication) && !os(tvOS)
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
    #else
    /// The asynchronous form of ``generateKey(_:sizeInBits:attributes:)``.
    @concurrent
    public func generateKey(
        _ keyType: KeyType,
        sizeInBits: Int,
        attributes: Attributes<CryptographicKey> = Attributes(),
    ) async throws(KeychainError) -> KeyReference {
        let synchronous: (KeyType, Int, Attributes<CryptographicKey>) throws(KeychainError) -> KeyReference = generateKey(_:sizeInBits:attributes:)
        return try synchronous(keyType, sizeInBits, attributes)
    }

    /// The asynchronous form of ``generateSecureEnclaveKey(applicationTag:label:accessGroup:accessibility:constraints:)``.
    @concurrent
    public func generateSecureEnclaveKey(
        applicationTag: Data? = nil,
        label: String? = nil,
        accessGroup: AccessGroup? = nil,
        accessibility: Accessibility = .whenUnlockedThisDeviceOnly,
        constraints: AccessControl.Flags = [],
    ) async throws(KeychainError) -> KeyReference {
        let synchronous: (Data?, String?, AccessGroup?, Accessibility, AccessControl.Flags) throws(KeychainError) -> KeyReference = generateSecureEnclaveKey(applicationTag:label:accessGroup:accessibility:constraints:)
        return try synchronous(applicationTag, label, accessGroup, accessibility, constraints)
    }
    #endif

    /// The asynchronous form of ``update(matching:with:)``.
    @concurrent
    public func update<Class>(matching query: Query<Class>, with changes: Item<Class>) async throws(KeychainError) {
        let synchronous: (Query<Class>, Item<Class>) throws(KeychainError) -> Void = update(matching:with:)
        try synchronous(query, changes)
    }

    /// The asynchronous form of ``delete(matching:)``.
    @concurrent
    public func delete<Class>(matching query: Query<Class>) async throws(KeychainError) {
        let synchronous: (Query<Class>) throws(KeychainError) -> Void = delete(matching:)
        try synchronous(query)
    }
}
