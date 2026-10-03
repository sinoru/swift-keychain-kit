//
//  Item.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

/// A keychain item of one class: its attributes and, for password classes, its secret data.
///
/// Passed to `Keychain.add(_:)` to create an item and to `Keychain.update(matching:with:)` to
/// describe the changes, and returned by the read operations.
public struct Item<Class: ItemClass>: Hashable, Sendable {
    public var attributes: Attributes<Class>

    /// The secret (`kSecValueData`). `nil` when the item was read without requesting data.
    public var data: Data?

    public init(attributes: Attributes<Class> = Attributes(), data: Data? = nil) {
        self.attributes = attributes
        self.data = data
    }

    public subscript<Value>(key: AttributeKey<Class, Value>) -> Value? {
        get { attributes[key] }
        set { attributes[key] = newValue }
    }

    public subscript<Value>(key: ReadOnlyAttributeKey<Class, Value>) -> Value? {
        attributes[key]
    }
}
