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
/// describe the changes, and returned by the read operations. Every attribute of `attributes`
/// is reachable directly on the item, so `item.service` and `item.attributes.service` are the
/// same thing.
public struct Item<Class: ItemClass>: Hashable, Sendable {
    /// Everything about the item except its secret.
    public var attributes: Attributes<Class>

    /// The secret (`kSecValueData`). `nil` on an item built by the caller without one; the read
    /// operations that return items always fill it in.
    public var data: Data?

    /// An item with the given attributes and secret.
    public init(attributes: Attributes<Class> = Attributes(), data: Data? = nil) {
        self.attributes = attributes
        self.data = data
    }
}
