//
//  Item+PasswordItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Foundation

extension Item where Class: PasswordItemClass {
    /// Forwards to `Attributes/account`.
    public var account: String? {
        get { attributes.account }
        set { attributes.account = newValue }
    }

    /// Forwards to `Attributes/description`.
    public var description: String? {
        get { attributes.description }
        set { attributes.description = newValue }
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
    /// The secret decoded as UTF-8.
    ///
    /// `nil` when there is no data or the data is not valid UTF-8. Setting it replaces `data`;
    /// setting `nil` clears it.
    public var password: String? {
        get { data.flatMap { String(data: $0, encoding: .utf8) } }
        set { data = newValue.map { Data($0.utf8) } }
    }
}
