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

    /// Adds an item and returns its persistent reference.
    ///
    /// Requesting the reference costs nothing extra, so it is always returned and may be ignored.
    /// Fails with `duplicateItem` when an item with the same primary key exists.
    @discardableResult
    public func add<Class>(_ item: borrowing Item<Class>) throws(KeychainError) -> PersistentReference {
        var dictionary = item.attributes.secDictionary
        dictionary[Keys.itemClass] = .string(Class.secClass as String)
        if let data = item.data {
            dictionary[Keys.valueData] = .data(data)
        }
        applyDefaults(to: &dictionary, forAdding: true)
        dictionary[Keys.returnPersistentRef] = .bool(true)

        guard case .data(let reference)? = try backend.add(dictionary) else {
            throw KeychainError(code: .decodingFailed)
        }
        return PersistentReference(rawValue: reference)
    }

    // MARK: Read

    /// The first matching item with its attributes and data, or `nil` when nothing matches.
    public func first<Class>(matching query: Query<Class>) throws(KeychainError) -> Item<Class>? {
        guard let value = try fetch(query, returning: [Keys.returnAttributes, Keys.returnData], all: false) else {
            return nil
        }
        return try Self.item(from: value)
    }

    /// The attributes of the first matching item, or `nil` when nothing matches.
    ///
    /// Reading attributes alone does not prompt for authentication, even for items protected
    /// by an access control object.
    public func attributes<Class>(matching query: Query<Class>) throws(KeychainError) -> Attributes<Class>? {
        guard let value = try fetch(query, returning: [Keys.returnAttributes], all: false) else {
            return nil
        }
        return try Self.attributes(from: value)
    }

    /// The data of the first matching item, or `nil` when nothing matches.
    public func data<Class>(matching query: Query<Class>) throws(KeychainError) -> Data? {
        guard let value = try fetch(query, returning: [Keys.returnData], all: false) else {
            return nil
        }
        return try Self.data(from: value)
    }

    /// The persistent reference of the first matching item, or `nil` when nothing matches.
    public func persistentReference<Class>(matching query: Query<Class>) throws(KeychainError) -> PersistentReference? {
        guard let value = try fetch(query, returning: [Keys.returnPersistentRef], all: false) else {
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
        guard case .array(let values)? = try fetch(query, returning: [Keys.returnAttributes, Keys.returnPersistentRef], all: true) else {
            return []
        }
        var items: [Item<Class>] = []
        items.reserveCapacity(values.count)
        for value in values {
            guard case .dictionary(var dictionary) = value,
                  case .data(let reference)? = dictionary.removeValue(forKey: Keys.valuePersistentRef)
            else {
                throw KeychainError(code: .decodingFailed)
            }
            let attributes = Attributes<Class>(secDictionary: dictionary)

            var dataQuery = Query<Class>()
            dataQuery.persistentReference = PersistentReference(rawValue: reference)
            dataQuery.synchronizable = .any
            // The item's own group, so a query for a non-default group is not redirected to the default.
            dataQuery[.accessGroup] = attributes[.accessGroup]
            items.append(Item(attributes: attributes, data: try data(matching: dataQuery)))
        }
        return items
    }

    /// The attributes of every matching item, in one call.
    public func allAttributes<Class>(matching query: Query<Class>) throws(KeychainError) -> [Attributes<Class>] {
        guard case .array(let values)? = try fetch(query, returning: [Keys.returnAttributes], all: true) else {
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
        guard case .array(let values)? = try fetch(query, returning: [Keys.returnPersistentRef], all: true) else {
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
        var attributes = changes.attributes.secDictionary
        if let data = changes.data {
            attributes[Keys.valueData] = .data(data)
        }
        try backend.update(dictionary(for: query), with: attributes)
    }

    // MARK: Delete

    /// Deletes every matching item. Nothing matching is not an error.
    public func delete<Class>(matching query: Query<Class>) throws(KeychainError) {
        do {
            try backend.delete(dictionary(for: query))
        } catch {
            guard error.code == .itemNotFound else {
                throw error
            }
        }
    }

    // MARK: Dictionary assembly

    /// Runs a search, returning `nil` instead of throwing when nothing matches.
    private func fetch<Class>(_ query: Query<Class>, returning keys: [String], all: Bool) throws(KeychainError) -> SecValue? {
        var dictionary = dictionary(for: query)
        for key in keys {
            dictionary[key] = .bool(true)
        }
        if all {
            dictionary[Keys.matchLimit] = .string(Keys.matchLimitAll)
        }
        do {
            return try backend.copyMatching(dictionary)
        } catch {
            guard error.code == .itemNotFound else {
                throw error
            }
            return nil
        }
    }

    private func dictionary<Class>(for query: Query<Class>) -> SecDictionary {
        var dictionary = query.secDictionary
        applyDefaults(to: &dictionary, forAdding: false)
        return dictionary
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

    // MARK: Result parsing

    private static func item<Class>(from value: SecValue) throws(KeychainError) -> Item<Class> {
        guard case .dictionary(var dictionary) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        let data: Data? = if case .data(let data)? = dictionary.removeValue(forKey: Keys.valueData) { data } else { nil }
        return Item(attributes: Attributes(secDictionary: dictionary), data: data)
    }

    private static func attributes<Class>(from value: SecValue) throws(KeychainError) -> Attributes<Class> {
        guard case .dictionary(let dictionary) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        return Attributes(secDictionary: dictionary)
    }

    private static func data(from value: SecValue) throws(KeychainError) -> Data {
        guard case .data(let data) = value else {
            throw KeychainError(code: .decodingFailed)
        }
        return data
    }

    private static func persistentReference(from value: SecValue) throws(KeychainError) -> PersistentReference {
        PersistentReference(rawValue: try data(from: value))
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
    #if os(macOS)
    static let useKeychain = kSecUseKeychain as String
    static let matchSearchList = kSecMatchSearchList as String
    static let matchItemList = kSecMatchItemList as String
    #endif
}
