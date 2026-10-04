//
//  Item.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// A keychain item of one class: its attributes and its value.
///
/// The value is secret data for the password classes (`data`) and a framework object for keys,
/// certificates, and identities (`reference`); each is declared only for the classes it applies
/// to. An item is passed to `Keychain.add(_:)` to create an item and to
/// `Keychain.update(matching:with:)` to describe the changes, and returned by the read
/// operations. Every attribute of `attributes` is reachable directly on the item, so
/// `item.service` and `item.attributes.service` are the same thing.
public struct Item<Class: ItemClass>: Hashable, Sendable {
    /// Everything about the item except its value.
    public var attributes: Attributes<Class>

    /// The value as it travels in a SecItem dictionary: `data` under `kSecValueData`, an
    /// `object` under `kSecValueRef`.
    package var value: SecValue?

    /// The entry the value occupies in a SecItem dictionary.
    package var valueEntry: (key: SecItemKey, value: SecValue)? {
        guard let value else {
            return nil
        }
        if case .object = value {
            return (.valueRef, value)
        }
        return (.valueData, value)
    }

    /// An item with the given attributes and no value.
    public init(attributes: Attributes<Class> = Attributes()) {
        self.attributes = attributes
    }
}
