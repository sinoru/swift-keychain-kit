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

    /// The asynchronous form of ``first(matching:)`` for the password classes.
    @concurrent
    public func first<Class: PasswordItemClass>(matching query: Query<Class>) async throws(KeychainError) -> Item<Class>? {
        let synchronous: (Query<Class>) throws(KeychainError) -> Item<Class>? = first(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``first(matching:)`` for keys, certificates, and identities.
    @concurrent
    public func first<Class: ReferenceItemClass>(matching query: Query<Class>) async throws(KeychainError) -> Item<Class>? {
        let synchronous: (Query<Class>) throws(KeychainError) -> Item<Class>? = first(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``attributes(matching:)``.
    @concurrent
    public func attributes<Class>(matching query: Query<Class>) async throws(KeychainError) -> Attributes<Class>? {
        let synchronous: (Query<Class>) throws(KeychainError) -> Attributes<Class>? = attributes(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``data(matching:)``.
    @concurrent
    public func data<Class: PasswordItemClass>(matching query: Query<Class>) async throws(KeychainError) -> Data? {
        let synchronous: (Query<Class>) throws(KeychainError) -> Data? = data(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``reference(matching:)``.
    @concurrent
    public func reference<Class: ReferenceItemClass>(matching query: Query<Class>) async throws(KeychainError) -> Class.Reference? {
        let synchronous: (Query<Class>) throws(KeychainError) -> Class.Reference? = reference(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``persistentReference(matching:)``.
    @concurrent
    public func persistentReference<Class>(matching query: Query<Class>) async throws(KeychainError) -> PersistentReference? {
        let synchronous: (Query<Class>) throws(KeychainError) -> PersistentReference? = persistentReference(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``all(matching:)`` for the password classes.
    @concurrent
    public func all<Class: PasswordItemClass>(matching query: Query<Class>) async throws(KeychainError) -> [Item<Class>] {
        let synchronous: (Query<Class>) throws(KeychainError) -> [Item<Class>] = all(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``all(matching:)`` for keys, certificates, and identities.
    @concurrent
    public func all<Class: ReferenceItemClass>(matching query: Query<Class>) async throws(KeychainError) -> [Item<Class>] {
        let synchronous: (Query<Class>) throws(KeychainError) -> [Item<Class>] = all(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``allAttributes(matching:)``.
    @concurrent
    public func allAttributes<Class>(matching query: Query<Class>) async throws(KeychainError) -> [Attributes<Class>] {
        let synchronous: (Query<Class>) throws(KeychainError) -> [Attributes<Class>] = allAttributes(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``allReferences(matching:)``.
    @concurrent
    public func allReferences<Class: ReferenceItemClass>(matching query: Query<Class>) async throws(KeychainError) -> [Class.Reference] {
        let synchronous: (Query<Class>) throws(KeychainError) -> [Class.Reference] = allReferences(matching:)
        return try synchronous(query)
    }

    /// The asynchronous form of ``allPersistentReferences(matching:)``.
    @concurrent
    public func allPersistentReferences<Class>(matching query: Query<Class>) async throws(KeychainError) -> [PersistentReference] {
        let synchronous: (Query<Class>) throws(KeychainError) -> [PersistentReference] = allPersistentReferences(matching:)
        return try synchronous(query)
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
