//
//  Attributes.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The attributes of a keychain item of one class, keyed by `AttributeKey`.
///
/// Protection is set through `protection` rather than a key, because `kSecAttrAccessible` and
/// `kSecAttrAccessControl` describe the same thing in two forms and Apple's guidance is to set
/// one or the other.
public struct Attributes<Class: ItemClass>: Hashable, Sendable {
    /// Every attribute except the access control object, by raw key.
    package var storage: SecDictionary

    /// Kept apart from `storage` so that a value set here reads back as the same value; the
    /// framework exposes a `SecAccessControl` object but not the constraints inside it.
    private var accessControl: AccessControl?

    /// No attributes set.
    public init() {
        storage = [:]
    }

    /// Builds attributes from a dictionary the framework returned.
    ///
    /// The class key is dropped because `Class` already carries it, and the `kSecValue*` entries
    /// are dropped because they are not attributes. An access control object becomes an opaque
    /// `AccessControl` whose constraints are unknown.
    package init(secDictionary: SecDictionary) {
        var storage = secDictionary
        storage[Keys.itemClass] = nil
        for key in Keys.values {
            storage[key] = nil
        }
        if case .object(let object)? = storage.removeValue(forKey: Keys.accessControl) {
            accessControl = AccessControl(opaque: object)
        }
        self.storage = storage
    }

    /// The dictionary entries for a `SecItem*` call, without the class key.
    package var secDictionary: SecDictionary {
        var dictionary = storage
        if let accessControl {
            dictionary[Keys.accessControl] = .object(accessControl.secObject)
        }
        return dictionary
    }

    /// Reads or writes one attribute. Setting `nil` removes it.
    public subscript<Value>(key: AttributeKey<Class, Value>) -> Value? {
        get { storage[key.rawKey].flatMap(key.decode) }
        set { storage[key.rawKey] = newValue.map(key.encode) }
    }

    /// Reads one framework-set attribute, such as a date.
    public subscript<Value>(key: ReadOnlyAttributeKey<Class, Value>) -> Value? {
        storage[key.rawKey].flatMap(key.decode)
    }

    /// How the item is protected: by device state alone, or by an access control object.
    ///
    /// Setting one form clears the other.
    public var protection: Protection? {
        get {
            if let accessControl {
                return .accessControl(accessControl)
            }
            if case .string(let rawValue)? = storage[Keys.accessible] {
                return .accessible(Accessibility(rawValue: rawValue))
            }
            return nil
        }
        set {
            switch newValue {
            case .accessible(let accessibility)?:
                accessControl = nil
                storage[Keys.accessible] = .string(accessibility.rawValue)
            case .accessControl(let control)?:
                storage[Keys.accessible] = nil
                accessControl = control
            case nil:
                storage[Keys.accessible] = nil
                accessControl = nil
            }
        }
    }

    /// Whether no attribute, including protection, is set.
    public var isEmpty: Bool {
        storage.isEmpty && accessControl == nil
    }
}

/// File-scoped because a type nested in a generic struct cannot hold static stored properties.
private enum Keys {
    static let itemClass = kSecClass as String
    static let accessible = kSecAttrAccessible as String
    static let accessControl = kSecAttrAccessControl as String
    static let values = [kSecValueData, kSecValueRef, kSecValuePersistentRef].map { $0 as String }
}
