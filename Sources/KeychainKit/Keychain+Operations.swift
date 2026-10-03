//
//  Keychain+Operations.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

extension Keychain {
    // MARK: Create

    #if canImport(LocalAuthentication)
    /// Adds an item and returns its persistent reference.
    ///
    /// Requesting the reference costs nothing extra, so it is always returned and may be ignored.
    /// Fails with `duplicateItem` when an item with the same primary key exists. An item whose
    /// access control requires an application password needs `authenticationContext` here too.
    @discardableResult
    public func add<Class>(
        _ item: borrowing Item<Class>,
        authenticationContext: AuthenticationContext? = nil,
    ) throws(KeychainError) -> PersistentReference {
        try Self.persistentReference(fromAdd: Self.secItemAdd(addDictionary(for: item, authenticationContext: authenticationContext)))
    }
    #else
    /// Adds an item and returns its persistent reference.
    ///
    /// Requesting the reference costs nothing extra, so it is always returned and may be ignored.
    /// Fails with `duplicateItem` when an item with the same primary key exists.
    @discardableResult
    public func add<Class>(_ item: borrowing Item<Class>) throws(KeychainError) -> PersistentReference {
        try Self.persistentReference(fromAdd: Self.secItemAdd(addDictionary(for: item)))
    }
    #endif

    // MARK: Read

    /// The first matching item with its attributes and data, or `nil` when nothing matches.
    public func first<Class>(matching query: Query<Class>) throws(KeychainError) -> Item<Class>? {
        guard let value = try fetch(query, returning: [.attributes, .data], all: false) else {
            return nil
        }
        return try Self.item(from: value)
    }

    /// The attributes of the first matching item, or `nil` when nothing matches.
    ///
    /// Reading attributes alone does not prompt for authentication, even for items protected
    /// by an access control object.
    public func attributes<Class>(matching query: Query<Class>) throws(KeychainError) -> Attributes<Class>? {
        guard let value = try fetch(query, returning: .attributes, all: false) else {
            return nil
        }
        return try Self.attributes(from: value)
    }

    /// The data of the first matching item, or `nil` when nothing matches.
    public func data<Class>(matching query: Query<Class>) throws(KeychainError) -> Data? {
        guard let value = try fetch(query, returning: .data, all: false) else {
            return nil
        }
        return try Self.data(from: value)
    }

    /// The persistent reference of the first matching item, or `nil` when nothing matches.
    public func persistentReference<Class>(matching query: Query<Class>) throws(KeychainError) -> PersistentReference? {
        guard let value = try fetch(query, returning: .persistentReference, all: false) else {
            return nil
        }
        return try Self.persistentReference(from: value)
    }

    /// Every matching item with its attributes and data.
    ///
    /// The framework does not return data for more than one password item at a time, so this
    /// fetches the attributes and persistent references in one call and the data of each item
    /// in a second. Use `allAttributes(matching:)` when the data is not needed.
    public func all<Class>(matching query: Query<Class>) throws(KeychainError) -> [Item<Class>] {
        guard case .array(let values)? = try fetch(query, returning: [.attributes, .persistentReference], all: true) else {
            return []
        }
        var items: [Item<Class>] = []
        items.reserveCapacity(values.count)
        for value in values {
            let (attributes, reference) = try Self.attributesAndReference(from: value) as (Attributes<Class>, PersistentReference)
            let data = try data(matching: dataQuery(for: attributes, reference: reference))
            items.append(Item(attributes: attributes, data: data))
        }
        return items
    }

    /// The attributes of every matching item, in one call.
    public func allAttributes<Class>(matching query: Query<Class>) throws(KeychainError) -> [Attributes<Class>] {
        guard case .array(let values)? = try fetch(query, returning: .attributes, all: true) else {
            return []
        }
        var attributes: [Attributes<Class>] = []
        attributes.reserveCapacity(values.count)
        for value in values {
            attributes.append(try Self.attributes(from: value))
        }
        return attributes
    }

    /// The persistent references of every matching item, in one call.
    public func allPersistentReferences<Class>(matching query: Query<Class>) throws(KeychainError) -> [PersistentReference] {
        guard case .array(let values)? = try fetch(query, returning: .persistentReference, all: true) else {
            return []
        }
        var references: [PersistentReference] = []
        references.reserveCapacity(values.count)
        for value in values {
            references.append(try Self.persistentReference(from: value))
        }
        return references
    }

    // MARK: Update

    /// Applies the attributes and data set on `changes` to every matching item.
    ///
    /// Unlike the read operations this throws `itemNotFound` when nothing matches, because an
    /// update presumes the item exists. Changing a primary-key attribute to collide with another
    /// item fails with `duplicateItem`.
    public func update<Class>(matching query: Query<Class>, with changes: borrowing Item<Class>) throws(KeychainError) {
        try Self.secItemUpdate(dictionary(for: query), with: Self.updateDictionary(for: changes))
    }

    // MARK: Delete

    /// Deletes every matching item. Nothing matching is not an error.
    public func delete<Class>(matching query: Query<Class>) throws(KeychainError) {
        do {
            try Self.secItemDelete(dictionary(for: query))
        } catch {
            guard error.code == .itemNotFound else {
                throw error
            }
        }
    }

    /// Runs a search, returning `nil` instead of throwing when nothing matches.
    private func fetch<Class>(_ query: Query<Class>, returning keys: ResultKeys, all: Bool) throws(KeychainError) -> SecValue? {
        do {
            return try Self.secItemCopyMatching(requestDictionary(for: query, returning: keys, all: all))
        } catch {
            guard error.code == .itemNotFound else {
                throw error
            }
            return nil
        }
    }
}

// MARK: - Request dictionaries

/// The pure half of each operation: what gets sent to the framework. Package-visible so the
/// tests can check it without a keychain.
extension Keychain {
    /// Which `kSecReturn*` keys a search asks for.
    package struct ResultKeys: OptionSet, Sendable {
        package let rawValue: UInt8

        package init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        package static let data = ResultKeys(rawValue: 1 << 0)
        package static let attributes = ResultKeys(rawValue: 1 << 1)
        package static let persistentReference = ResultKeys(rawValue: 1 << 2)
    }

    #if canImport(LocalAuthentication)
    /// The dictionary for `SecItemAdd`.
    package func addDictionary<Class>(
        for item: borrowing Item<Class>,
        authenticationContext: AuthenticationContext?,
    ) -> SecDictionary {
        var dictionary = addDictionary(for: item)
        if let authenticationContext {
            dictionary[Keys.useAuthenticationContext] = authenticationContext.secValue
        }
        return dictionary
    }
    #endif

    /// The dictionary for `SecItemAdd`, before any authentication context.
    package func addDictionary<Class>(for item: borrowing Item<Class>) -> SecDictionary {
        var dictionary = item.attributes.secDictionary
        dictionary[Keys.itemClass] = .string(Class.secClass as String)
        if let data = item.data {
            dictionary[Keys.valueData] = .data(data)
        }
        applyDefaults(to: &dictionary, forAdding: true)
        dictionary[Keys.returnPersistentRef] = .bool(true)
        return dictionary
    }

    /// The dictionary for `SecItemCopyMatching`.
    package func requestDictionary<Class>(for query: Query<Class>, returning keys: ResultKeys, all: Bool) -> SecDictionary {
        var dictionary = baseDictionary(for: query)
        if keys.contains(.data) {
            dictionary[Keys.returnData] = .bool(true)
        }
        if keys.contains(.attributes) {
            dictionary[Keys.returnAttributes] = .bool(true)
        }
        if keys.contains(.persistentReference) {
            dictionary[Keys.returnPersistentRef] = .bool(true)
        }
        if all {
            dictionary[Keys.matchLimit] = .string(Keys.matchLimitAll)
        }
        return dictionary
    }

    /// The dictionary for `SecItemUpdate` and `SecItemDelete`.
    ///
    /// Apple documents both as acting on every match by default, and the data protection
    /// keychain does. The file-based keychain on macOS touches only the first match unless
    /// `kSecMatchLimitAll` is given, so it is always given; the other implementation ignores it.
    package func dictionary<Class>(for query: Query<Class>) -> SecDictionary {
        var dictionary = baseDictionary(for: query)
        dictionary[Keys.matchLimit] = .string(Keys.matchLimitAll)
        return dictionary
    }

    /// The query's own entries plus the access group and storage defaults.
    private func baseDictionary<Class>(for query: Query<Class>) -> SecDictionary {
        var dictionary = query.secDictionary
        applyDefaults(to: &dictionary, forAdding: false)
        return dictionary
    }

    /// The second dictionary for `SecItemUpdate`: only what `changes` sets.
    package static func updateDictionary<Class>(for changes: borrowing Item<Class>) -> SecDictionary {
        var attributes = changes.attributes.secDictionary
        if let data = changes.data {
            attributes[Keys.valueData] = .data(data)
        }
        return attributes
    }

    /// The per-item query `all(matching:)` uses to fetch data by persistent reference.
    ///
    /// It carries the item's own access group so that a search in a non-default group is not
    /// redirected to the default, and matches synchronizable items too.
    package func dataQuery<Class>(for attributes: Attributes<Class>, reference: PersistentReference) -> Query<Class> {
        var query = Query<Class>()
        query.persistentReference = reference
        query.synchronizable = .any
        query[.accessGroup] = attributes[.accessGroup]
        return query
    }

    /// Adds the access group and storage entries. A group named by the caller wins over the default.
    private func applyDefaults(to dictionary: inout SecDictionary, forAdding: Bool) {
        if let accessGroup, dictionary[Keys.accessGroup] == nil {
            dictionary[Keys.accessGroup] = .string(accessGroup.rawValue)
        }
        switch storage {
        case .dataProtection:
            dictionary[Keys.useDataProtectionKeychain] = .bool(true)
        #if os(macOS)
        case .fileBased(let keychain):
            if let keychain {
                let reference = SecValue.object(SecObject(keychain.reference))
                if forAdding {
                    dictionary[Keys.useKeychain] = reference
                } else {
                    dictionary[Keys.matchSearchList] = .array([reference])
                }
            }
            // The file-based keychain resolves persistent references through the item list,
            // not through kSecValuePersistentRef as the data protection keychain does.
            if let reference = dictionary.removeValue(forKey: Keys.valuePersistentRef) {
                dictionary[Keys.matchItemList] = .array([reference])
            }
        #endif
        }
    }
}

// MARK: - Result parsing

/// The other pure half: what comes back from the framework. A value of an unexpected shape is
/// reported as `decodingFailed`.
extension Keychain {
    package static func item<Class>(from value: SecValue) throws(KeychainError) -> Item<Class> {
        guard case .dictionary(var dictionary) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        let data: Data? = if case .data(let data)? = dictionary.removeValue(forKey: Keys.valueData) { data } else { nil }
        return Item(attributes: Attributes(secDictionary: dictionary), data: data)
    }

    package static func attributes<Class>(from value: SecValue) throws(KeychainError) -> Attributes<Class> {
        guard case .dictionary(let dictionary) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        return Attributes(secDictionary: dictionary)
    }

    package static func attributesAndReference<Class>(from value: SecValue) throws(KeychainError) -> (Attributes<Class>, PersistentReference) {
        guard case .dictionary(var dictionary) = value,
              case .data(let reference)? = dictionary.removeValue(forKey: Keys.valuePersistentRef)
        else {
            throw KeychainError(code: .decodingFailed)
        }
        return (Attributes(secDictionary: dictionary), PersistentReference(rawValue: reference))
    }

    package static func data(from value: SecValue) throws(KeychainError) -> Data {
        guard case .data(let data) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        return data
    }

    package static func persistentReference(from value: SecValue) throws(KeychainError) -> PersistentReference {
        PersistentReference(rawValue: try data(from: value))
    }

    /// `SecItemAdd` returns nothing unless asked; a missing reference is a decoding failure.
    package static func persistentReference(fromAdd value: SecValue?) throws(KeychainError) -> PersistentReference {
        guard let value else {
            throw KeychainError(code: .decodingFailed)
        }
        return try persistentReference(from: value)
    }
}

private enum Keys {
    static let itemClass = kSecClass as String
    static let accessGroup = kSecAttrAccessGroup as String
    static let valueData = kSecValueData as String
    static let valuePersistentRef = kSecValuePersistentRef as String
    static let returnData = kSecReturnData as String
    static let returnAttributes = kSecReturnAttributes as String
    static let returnPersistentRef = kSecReturnPersistentRef as String
    static let matchLimit = kSecMatchLimit as String
    static let matchLimitAll = kSecMatchLimitAll as String
    static let useDataProtectionKeychain = kSecUseDataProtectionKeychain as String
    #if canImport(LocalAuthentication)
    static let useAuthenticationContext = kSecUseAuthenticationContext as String
    #endif
    #if os(macOS)
    static let useKeychain = kSecUseKeychain as String
    static let matchSearchList = kSecMatchSearchList as String
    static let matchItemList = kSecMatchItemList as String
    #endif
}
