//
//  Keychain+Operations.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Keychain {
    // MARK: Create

    #if canImport(LocalAuthentication) && !os(tvOS)
    /// Adds an item and returns its persistent reference.
    ///
    /// Requesting the reference costs nothing extra, so it is always returned and may be ignored.
    /// Fails with `duplicateItem` when an item with the same primary key exists. An item whose
    /// access control requires an application password needs `authenticationContext` here too.
    @discardableResult
    public func add<Class>(
        _ item: Item<Class>,
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
    public func add<Class>(_ item: Item<Class>) throws(KeychainError) -> PersistentReference {
        try Self.persistentReference(fromAdd: Self.secItemAdd(addDictionary(for: item)))
    }
    #endif

    // MARK: Read

    /// The first matching item with its attributes and data, or `nil` when nothing matches.
    public func first<Class: PasswordItemClass>(matching query: Query<Class>) throws(KeychainError) -> Item<Class>? {
        guard let value = try fetch(query, returning: [.attributes, .data], all: false) else {
            return nil
        }
        return try Self.item(from: value)
    }

    /// The first matching item with its attributes and reference, or `nil` when nothing matches.
    public func first<Class: ReferenceItemClass>(matching query: Query<Class>) throws(KeychainError) -> Item<Class>? {
        guard let value = try fetch(query, returning: [.attributes, .reference], all: false) else {
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
    public func data<Class: PasswordItemClass>(matching query: Query<Class>) throws(KeychainError) -> Data? {
        guard let value = try fetch(query, returning: .data, all: false) else {
            return nil
        }
        return try Self.data(from: value)
    }

    /// The reference of the first matching item, or `nil` when nothing matches.
    public func reference<Class: ReferenceItemClass>(matching query: Query<Class>) throws(KeychainError) -> Class.Reference? {
        guard let value = try fetch(query, returning: .reference, all: false) else {
            return nil
        }
        return try Self.reference(from: value)
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
    /// in a second. An item whose data cannot be fetched in that second call, because the query
    /// skips items requiring authentication or because the item was removed in between, is left
    /// out rather than returned without data. Use `allAttributes(matching:)` when the data is
    /// not needed.
    public func all<Class: PasswordItemClass>(matching query: Query<Class>) throws(KeychainError) -> [Item<Class>] {
        guard case .array(let values)? = try fetch(query, returning: [.attributes, .persistentReference], all: true) else {
            return []
        }
        var items: [Item<Class>] = []
        items.reserveCapacity(values.count)
        for value in values {
            let (attributes, reference) = try Self.attributesAndReference(from: value) as (Attributes<Class>, PersistentReference)
            guard let data = try data(matching: dataQuery(for: attributes, reference: reference, inheriting: query)) else {
                continue
            }
            items.append(Item(attributes: attributes, data: data))
        }
        return items
    }

    /// Every matching item with its attributes and reference, in one call.
    public func all<Class: ReferenceItemClass>(matching query: Query<Class>) throws(KeychainError) -> [Item<Class>] {
        guard case .array(let values)? = try fetch(query, returning: [.attributes, .reference], all: true) else {
            return []
        }
        var items: [Item<Class>] = []
        items.reserveCapacity(values.count)
        for value in values {
            items.append(try Self.item(from: value))
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

    /// The references of every matching item, in one call.
    public func allReferences<Class: ReferenceItemClass>(matching query: Query<Class>) throws(KeychainError) -> [Class.Reference] {
        guard case .array(let values)? = try fetch(query, returning: .reference, all: true) else {
            return []
        }
        var references: [Class.Reference] = []
        references.reserveCapacity(values.count)
        for value in values {
            references.append(try Self.reference(from: value))
        }
        return references
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
    ///
    /// A reference on `changes` is left out: an update cannot replace the key or certificate an
    /// item is. That lets an item that was read be changed and passed back as is. The exception
    /// is a key in the file-based keychain on macOS, which rejects most key attributes in an
    /// update even when their values are unchanged; there, pass an item holding only the
    /// attributes to change.
    public func update<Class>(matching query: Query<Class>, with changes: Item<Class>) throws(KeychainError) {
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
        package static let reference = ResultKeys(rawValue: 1 << 3)
    }

    #if canImport(LocalAuthentication) && !os(tvOS)
    /// The dictionary for `SecItemAdd`.
    package func addDictionary<Class>(
        for item: Item<Class>,
        authenticationContext: AuthenticationContext?,
    ) -> SecDictionary {
        var dictionary = addDictionary(for: item)
        if let authenticationContext {
            dictionary[.useAuthenticationContext] = authenticationContext.secValue
        }
        return dictionary
    }
    #endif

    /// The dictionary for `SecItemAdd`, before any authentication context.
    package func addDictionary<Class>(for item: Item<Class>) -> SecDictionary {
        var dictionary = item.attributes.secDictionary
        dictionary[.itemClass] = .string(Class.secClass)
        if let (key, value) = item.valueEntry {
            dictionary[key] = value
        }
        applyDefaults(to: &dictionary, forAdding: true)
        dictionary[.returnPersistentRef] = .bool(true)
        return dictionary
    }

    /// The dictionary for `SecItemCopyMatching`.
    ///
    /// This is the only call that accepts `kSecUseAuthenticationUISkip`; update and delete
    /// reject it with `errSecParam`, so it is added here rather than in the query itself.
    package func requestDictionary<Class>(for query: Query<Class>, returning keys: ResultKeys, all: Bool) -> SecDictionary {
        var dictionary = baseDictionary(for: query)
        if query.skipsItemsRequiringAuthentication {
            dictionary[.useAuthenticationUI] = .useAuthenticationUISkip
        }
        if keys.contains(.data) {
            dictionary[.returnData] = .bool(true)
        }
        if keys.contains(.attributes) {
            dictionary[.returnAttributes] = .bool(true)
        }
        if keys.contains(.persistentReference) {
            dictionary[.returnPersistentRef] = .bool(true)
        }
        if keys.contains(.reference) {
            dictionary[.returnRef] = .bool(true)
        }
        if all {
            dictionary[.matchLimit] = .matchLimitAll
        }
        return dictionary
    }

    /// The dictionary for `SecItemUpdate` and `SecItemDelete`.
    ///
    /// Apple documents both as acting on every match by default, and the data protection
    /// keychain does. It also rejects a `kSecMatchLimit` in these two calls with `errSecParam`,
    /// for every item class (measured on the iOS 27 simulator with an entitled host app). The
    /// file-based keychain on macOS is the opposite: it touches only the first match unless
    /// `kSecMatchLimitAll` is given. So the limit is given there and nowhere else.
    package func dictionary<Class>(for query: Query<Class>) -> SecDictionary {
        var dictionary = baseDictionary(for: query)
        #if os(macOS)
        if case .fileBased = storage {
            dictionary[.matchLimit] = .matchLimitAll
        }
        #endif
        return dictionary
    }

    /// The query's own entries plus the access group and storage defaults.
    private func baseDictionary<Class>(for query: Query<Class>) -> SecDictionary {
        var dictionary = query.secDictionary
        applyDefaults(to: &dictionary, forAdding: false)
        return dictionary
    }

    /// The second dictionary for `SecItemUpdate`: only what `changes` sets.
    ///
    /// Data is sent and a reference is not. The data protection keychain rejects `kSecValueRef`
    /// here with `errSecNoSuchAttr` (measured on the iOS 27 simulator with an entitled host app),
    /// and every item the read operations return for a key, certificate, or identity carries one.
    package static func updateDictionary<Class>(for changes: Item<Class>) -> SecDictionary {
        var attributes = changes.attributes.secDictionary
        if case .data? = changes.value {
            attributes[.valueData] = changes.value
        }
        return attributes
    }

    /// The per-item query `all(matching:)` uses to fetch data by persistent reference.
    ///
    /// It carries the item's own access group so that a search in a non-default group is not
    /// redirected to the default, matches synchronizable items too, and inherits the original
    /// query's authentication settings. Both are needed in the second step: reading attributes
    /// does not require authentication, so the first call returns protected items even when
    /// asked to skip them, and it is the data fetch that must skip or authenticate.
    package func dataQuery<Class>(
        for attributes: Attributes<Class>,
        reference: PersistentReference,
        inheriting original: Query<Class>,
    ) -> Query<Class> {
        var query = Query<Class>()
        query.persistentReference = reference
        query.synchronizable = .any
        query.accessGroup = attributes.accessGroup
        query.skipsItemsRequiringAuthentication = original.skipsItemsRequiringAuthentication
        #if canImport(LocalAuthentication) && !os(tvOS)
        query.authenticationContext = original.authenticationContext
        #endif
        return query
    }

    /// Adds the access group and storage entries. A group named by the caller wins over the default.
    private func applyDefaults(to dictionary: inout SecDictionary, forAdding: Bool) {
        if let accessGroup, dictionary[.accessGroup] == nil {
            dictionary[.accessGroup] = .string(accessGroup.rawValue)
        }
        switch storage {
        case .dataProtection:
            dictionary[.useDataProtectionKeychain] = .bool(true)
        #if os(macOS)
        case .fileBased(let keychain):
            if let keychain {
                let reference = SecValue.object(SecObject(keychain.reference))
                if forAdding {
                    dictionary[.useKeychain] = reference
                } else {
                    dictionary[.matchSearchList] = .array([reference])
                }
            }
            // The file-based keychain resolves persistent references through the item list,
            // not through kSecValuePersistentRef as the data protection keychain does.
            if let reference = dictionary.removeValue(forKey: .valuePersistentRef) {
                dictionary[.matchItemList] = .array([reference])
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
        guard case .dictionary(let dictionary) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        var item = Item<Class>(attributes: Attributes(secDictionary: dictionary))
        item.value = dictionary[.valueData] ?? dictionary[.valueRef]
        return item
    }

    package static func attributes<Class>(from value: SecValue) throws(KeychainError) -> Attributes<Class> {
        guard case .dictionary(let dictionary) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        return Attributes(secDictionary: dictionary)
    }

    package static func attributesAndReference<Class>(from value: SecValue) throws(KeychainError) -> (Attributes<Class>, PersistentReference) {
        guard case .dictionary(var dictionary) = value,
              case .data(let reference)? = dictionary.removeValue(forKey: .valuePersistentRef)
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

    /// An object of another type than the class's reference wraps is a decoding failure.
    package static func reference<Reference: ItemReference>(from value: SecValue) throws(KeychainError) -> Reference {
        guard case .object(let object) = value, let reference = Reference(object.reference) else {
            throw KeychainError(code: .decodingFailed)
        }
        return reference
    }

    package static func persistentReference(from value: SecValue) throws(KeychainError) -> PersistentReference {
        PersistentReference(rawValue: try data(from: value))
    }

    /// `SecItemAdd` returns nothing unless asked; a missing reference is a decoding failure.
    ///
    /// The file-based keychain on macOS answers an add made through `kSecValueRef` with a
    /// one-element array around the reference, where every other add returns the reference
    /// itself (measured on macOS 26). Both shapes are accepted.
    package static func persistentReference(fromAdd value: SecValue?) throws(KeychainError) -> PersistentReference {
        switch value {
        case .array(let values)? where values.count == 1:
            try persistentReference(from: values[0])
        case let value?:
            try persistentReference(from: value)
        case nil:
            throw KeychainError(code: .decodingFailed)
        }
    }
}
