//
//  Attributes.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The attributes of a keychain item of one class.
///
/// Each attribute is a property, declared only for the item classes it is valid for: `service`
/// exists on a generic password, `server` and `port` on an internet password, `label` and
/// `accessGroup` on everything. Attributes the framework sets, such as `creationDate`, are
/// read-only properties. Protection is set through `protection` rather than two separate
/// attributes, because `kSecAttrAccessible` and `kSecAttrAccessControl` describe the same thing
/// in two forms and Apple's guidance is to set one or the other.
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
        storage[.itemClass] = nil
        storage[.valueData] = nil
        storage[.valueRef] = nil
        storage[.valuePersistentRef] = nil
        if case .object(let object)? = storage.removeValue(forKey: .accessControl) {
            accessControl = AccessControl(opaque: object)
        }
        self.storage = storage
    }

    /// The dictionary entries for a `SecItem*` call, without the class key.
    package var secDictionary: SecDictionary {
        var dictionary = storage
        if let accessControl {
            dictionary[.accessControl] = .object(accessControl.secObject)
        }
        return dictionary
    }

    /// How the item is protected: by device state alone, or by an access control object.
    ///
    /// Setting one form clears the other.
    public var protection: Protection? {
        get {
            if let accessControl {
                return .accessControl(accessControl)
            }
            if case .string(let rawValue)? = storage[.accessible] {
                return .accessible(Accessibility(rawValue: rawValue))
            }
            return nil
        }
        set {
            switch newValue {
            case .accessible(let accessibility)?:
                accessControl = nil
                storage[.accessible] = .string(accessibility.rawValue)
            case .accessControl(let control)?:
                storage[.accessible] = nil
                accessControl = control
            case nil:
                storage[.accessible] = nil
                accessControl = nil
            }
        }
    }

    /// Whether no attribute, including protection, is set.
    public var isEmpty: Bool {
        storage.isEmpty && accessControl == nil
    }
}
