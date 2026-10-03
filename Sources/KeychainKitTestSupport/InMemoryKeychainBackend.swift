//
//  InMemoryKeychainBackend.swift
//  KeychainKitTestSupport
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
public import KeychainKit
internal import Security
internal import SynchronizationKit

/// A `KeychainBackend` that mimics `SecItem*` semantics without touching a real keychain.
///
/// It implements the behaviour the SecItem headers and Apple's documentation spell out:
/// per-class primary keys and `errSecDuplicateItem` on collision, `errSecItemNotFound` on a
/// miss, creation and modification dates, `kSecAttrSynchronizable` filtering, `kSecMatchLimit`,
/// and the result shape for each combination of `kSecReturn*` keys. Behaviour the documentation
/// leaves unspecified is not guessed at; see the notes on each operation.
///
/// Matching is plain equality on every attribute in the query. The `kSecMatch*` options other
/// than `kSecMatchLimit` are not interpreted, so a query that uses them simply matches nothing.
public final class InMemoryKeychainBackend: KeychainBackend, Sendable {
    struct StoredItem: Sendable {
        var attributes: SecDictionary
        var data: Data?
        var reference: SecObject?
        let persistentReference: Data
    }

    private struct State: Sendable {
        var items: [StoredItem] = []
        var nextPersistentReference = 1
    }

    private let state = Mutex(State())

    /// Supplies the creation and modification dates, so tests can control time.
    private let now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    /// The number of items currently stored.
    public var itemCount: Int {
        state.withLock { $0.items.count }
    }

    /// Removes every item.
    public func removeAll() {
        state.withLock { $0.items.removeAll() }
    }

    // MARK: KeychainBackend

    /// Assumes `kSecClass` is required and reports its absence as `errSecParam`; the real
    /// framework's behaviour for a missing class is not documented.
    @discardableResult
    package func add(_ attributes: SecDictionary) throws(KeychainError) -> SecValue? {
        let now = now()
        let result = state.withLock { state -> Result<SecValue?, KeychainError> in
            guard attributes[Keys.itemClass] != nil else {
                return .failure(KeychainError(code: .invalidParameter))
            }
            var stored = attributes.filter { !Keys.transient.contains($0.key) }
            stored[Keys.creationDate] = .date(now)
            stored[Keys.modificationDate] = .date(now)
            if state.items.contains(where: { Self.sharePrimaryKey($0.attributes, stored) }) {
                return .failure(KeychainError(code: .duplicateItem))
            }
            let item = StoredItem(
                attributes: stored,
                data: attributes[Keys.valueData].flatMap(\.dataValue),
                reference: attributes[Keys.valueRef].flatMap(\.objectValue),
                persistentReference: Data("inmemory-\(state.nextPersistentReference)".utf8),
            )
            state.nextPersistentReference += 1
            state.items.append(item)
            return .success(Self.shape(item, for: attributes))
        }
        return try result.get()
    }

    package func copyMatching(_ query: SecDictionary) throws(KeychainError) -> SecValue? {
        let result = state.withLock { state -> Result<SecValue?, KeychainError> in
            guard query[Keys.itemClass] != nil else {
                return .failure(KeychainError(code: .invalidParameter))
            }
            let matched = state.items.filter { Self.matches($0, query) }
            guard !matched.isEmpty else {
                return .failure(KeychainError(code: .itemNotFound))
            }
            guard let limit = Self.limit(in: query) else {
                return .success(Self.shape(matched[0], for: query))
            }
            let shaped = matched.prefix(limit).compactMap { Self.shape($0, for: query) }
            return .success(shaped.isEmpty ? nil : .array(shaped))
        }
        return try result.get()
    }

    package func update(_ query: SecDictionary, with attributes: SecDictionary) throws(KeychainError) {
        let now = now()
        let result = state.withLock { state -> Result<Void, KeychainError> in
            guard query[Keys.itemClass] != nil else {
                return .failure(KeychainError(code: .invalidParameter))
            }
            let indices = state.items.indices.filter { Self.matches(state.items[$0], query) }
            guard !indices.isEmpty else {
                return .failure(KeychainError(code: .itemNotFound))
            }
            var updated = state.items
            for index in indices {
                for (key, value) in attributes {
                    if key == Keys.valueData {
                        updated[index].data = value.dataValue
                    } else if key == Keys.valueRef {
                        updated[index].reference = value.objectValue
                    } else if !Keys.transient.contains(key) {
                        updated[index].attributes[key] = value
                    }
                }
                updated[index].attributes[Keys.modificationDate] = .date(now)
            }
            for index in indices {
                let collides = updated.indices.contains { other in
                    other != index && Self.sharePrimaryKey(updated[other].attributes, updated[index].attributes)
                }
                if collides {
                    return .failure(KeychainError(code: .duplicateItem))
                }
            }
            state.items = updated
            return .success(())
        }
        return try result.get()
    }

    package func delete(_ query: SecDictionary) throws(KeychainError) {
        let result = state.withLock { state -> Result<Void, KeychainError> in
            guard query[Keys.itemClass] != nil else {
                return .failure(KeychainError(code: .invalidParameter))
            }
            let before = state.items.count
            state.items.removeAll { Self.matches($0, query) }
            guard state.items.count < before else {
                return .failure(KeychainError(code: .itemNotFound))
            }
            return .success(())
        }
        return try result.get()
    }

    // MARK: Matching

    private static func matches(_ item: StoredItem, _ query: SecDictionary) -> Bool {
        guard item.attributes[Keys.itemClass] == query[Keys.itemClass] else {
            return false
        }
        if let persistentReference = query[Keys.valuePersistentRef]?.dataValue,
           persistentReference != item.persistentReference {
            return false
        }
        // Without the key a query sees only non-synchronizable items; `kSecAttrSynchronizableAny`
        // lifts the filter. Both rules come from the header comment on `kSecAttrSynchronizable`.
        switch query[Keys.synchronizable] {
        case nil:
            guard !isSynchronizable(item.attributes) else { return false }
        case .bool(let wanted)?:
            guard isSynchronizable(item.attributes) == wanted else { return false }
        case .string(Keys.synchronizableAny)?:
            break
        default:
            return false
        }
        for (key, value) in query where !Keys.nonMatching.contains(key) {
            guard item.attributes[key] == value else {
                return false
            }
        }
        return true
    }

    private static func isSynchronizable(_ attributes: SecDictionary) -> Bool {
        attributes[Keys.synchronizable] == .bool(true)
    }

    /// Two attribute sets collide when they agree on every primary-key attribute of their class.
    /// The primary keys per class are listed in the `SecItem.h` header comment for `kSecClass`.
    private static func sharePrimaryKey(_ lhs: SecDictionary, _ rhs: SecDictionary) -> Bool {
        guard let itemClass = lhs[Keys.itemClass]?.stringValue, lhs[Keys.itemClass] == rhs[Keys.itemClass] else {
            return false
        }
        guard isSynchronizable(lhs) == isSynchronizable(rhs) else {
            return false
        }
        return Keys.primaryKeys(forClass: itemClass).allSatisfy { lhs[$0] == rhs[$0] }
    }

    /// `nil` means the default of one item, returned bare rather than in an array.
    private static func limit(in query: SecDictionary) -> Int? {
        switch query[Keys.matchLimit] {
        case .string(Keys.matchLimitAll)?:
            Int.max
        case .number(let count)? where count > 1:
            count
        default:
            nil
        }
    }

    // MARK: Result shape

    /// One return key yields the value itself; several yield a dictionary of the attributes
    /// plus `kSecValue*` entries; none yields nothing. This is the shape Apple documents for
    /// `SecItemCopyMatching` and `SecItemAdd`.
    private static func shape(_ item: StoredItem, for query: SecDictionary) -> SecValue? {
        let wantsData = query[Keys.returnData] == .bool(true)
        let wantsAttributes = query[Keys.returnAttributes] == .bool(true)
        let wantsReference = query[Keys.returnRef] == .bool(true)
        let wantsPersistentReference = query[Keys.returnPersistentRef] == .bool(true)

        var values: [(key: String, value: SecValue)] = []
        if wantsData, let data = item.data {
            values.append((Keys.valueData, .data(data)))
        }
        if wantsReference, let reference = item.reference {
            values.append((Keys.valueRef, .object(reference)))
        }
        if wantsPersistentReference {
            values.append((Keys.valuePersistentRef, .data(item.persistentReference)))
        }

        let requested = [wantsData, wantsAttributes, wantsReference, wantsPersistentReference].count { $0 }
        switch requested {
        case 0:
            return nil
        case 1 where wantsAttributes:
            return .dictionary(item.attributes)
        case 1:
            return values.first?.value
        default:
            var dictionary = wantsAttributes ? item.attributes : [:]
            for (key, value) in values {
                dictionary[key] = value
            }
            return .dictionary(dictionary)
        }
    }

    // MARK: Keys

    private enum Keys {
        static let itemClass = kSecClass as String
        static let valueData = kSecValueData as String
        static let valueRef = kSecValueRef as String
        static let valuePersistentRef = kSecValuePersistentRef as String
        static let returnData = kSecReturnData as String
        static let returnAttributes = kSecReturnAttributes as String
        static let returnRef = kSecReturnRef as String
        static let returnPersistentRef = kSecReturnPersistentRef as String
        static let matchLimit = kSecMatchLimit as String
        static let matchLimitAll = kSecMatchLimitAll as String
        static let synchronizable = kSecAttrSynchronizable as String
        static let synchronizableAny = kSecAttrSynchronizableAny as String
        static let creationDate = kSecAttrCreationDate as String
        static let modificationDate = kSecAttrModificationDate as String

        /// Keys that describe the call rather than the item, and so are neither stored nor matched.
        static let transient: Set<String> = {
            var keys: Set<String> = [
                valueData, valueRef, valuePersistentRef,
                returnData, returnAttributes, returnRef, returnPersistentRef,
                matchLimit,
                kSecUseDataProtectionKeychain as String,
                kSecUseAuthenticationContext as String,
                kSecUseAuthenticationUI as String,
            ]
            #if os(macOS)
            keys.insert(kSecUseKeychain as String)
            keys.insert(kSecMatchSearchList as String)
            #endif
            return keys
        }()

        /// Keys excluded from attribute equality because `matches` handles them itself.
        static let nonMatching: Set<String> = transient.union([itemClass, synchronizable])

        static let genericPassword = kSecClassGenericPassword as String
        static let internetPassword = kSecClassInternetPassword as String
        static let certificate = kSecClassCertificate as String
        static let key = kSecClassKey as String
        static let identity = kSecClassIdentity as String

        static func primaryKeys(forClass itemClass: String) -> [String] {
            var keys = [kSecAttrAccessGroup]
            switch itemClass {
            case genericPassword:
                keys += [kSecAttrAccount, kSecAttrService]
            case internetPassword:
                keys += [
                    kSecAttrAccount, kSecAttrAuthenticationType, kSecAttrPath, kSecAttrPort,
                    kSecAttrProtocol, kSecAttrSecurityDomain, kSecAttrServer,
                ]
            case certificate, identity:
                keys += [kSecAttrCertificateType, kSecAttrIssuer, kSecAttrSerialNumber]
            case key:
                keys += [
                    kSecAttrApplicationLabel, kSecAttrApplicationTag, kSecAttrEffectiveKeySize,
                    kSecAttrKeyClass, kSecAttrKeySizeInBits, kSecAttrKeyType,
                ]
            default:
                break
            }
            return keys.map { $0 as String }
        }
    }
}

extension SecValue {
    fileprivate var stringValue: String? {
        if case .string(let value) = self { value } else { nil }
    }

    fileprivate var dataValue: Data? {
        if case .data(let value) = self { value } else { nil }
    }

    fileprivate var objectValue: SecObject? {
        if case .object(let value) = self { value } else { nil }
    }
}
