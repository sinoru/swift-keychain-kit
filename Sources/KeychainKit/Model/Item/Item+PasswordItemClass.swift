//
//  Item+PasswordItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Item where Class: PasswordItemClass {
    /// Forwards to `Attributes/account`.
    public var account: String? {
        get { attributes.account }
        set { attributes.account = newValue }
    }

    /// Forwards to `Attributes/itemDescription`.
    public var itemDescription: String? {
        get { attributes.itemDescription }
        set { attributes.itemDescription = newValue }
    }

    /// Forwards to `Attributes/comment`.
    public var comment: String? {
        get { attributes.comment }
        set { attributes.comment = newValue }
    }

    /// Forwards to `Attributes/creator`.
    public var creator: UInt32? {
        get { attributes.creator }
        set { attributes.creator = newValue }
    }

    /// Forwards to `Attributes/type`.
    public var type: UInt32? {
        get { attributes.type }
        set { attributes.type = newValue }
    }

    /// Forwards to `Attributes/isInvisible`.
    public var isInvisible: Bool? {
        get { attributes.isInvisible }
        set { attributes.isInvisible = newValue }
    }

    /// Forwards to `Attributes/isNegative`.
    public var isNegative: Bool? {
        get { attributes.isNegative }
        set { attributes.isNegative = newValue }
    }
}

extension Item where Class: PasswordItemClass {
    /// The secret (`kSecValueData`). `nil` on an item built by the caller without one; the read
    /// operations that return items always fill it in.
    public var data: Data? {
        get { value?.data }
        set { value = newValue.map(SecValue.data) }
    }

    /// An item with the given attributes and secret.
    public init(attributes: Attributes<Class> = Attributes(), data: Data?) {
        self.init(attributes: attributes)
        self.data = data
    }

    /// The secret decoded as UTF-8.
    ///
    /// `nil` when there is no data or the data is not valid UTF-8. Setting it replaces `data`;
    /// setting `nil` clears it.
    public var password: String? {
        get { data.flatMap { String(data: $0, encoding: .utf8) } }
        set { data = newValue.map { Data($0.utf8) } }
    }
}
