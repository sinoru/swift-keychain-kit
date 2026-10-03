//
//  Query+PasswordItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

extension Query where Class: PasswordItemClass {
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
