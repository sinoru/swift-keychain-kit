//
//  Attributes+PasswordItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The two password classes share most of their attributes.
public protocol PasswordItemClass: ItemClass {}

extension GenericPassword: PasswordItemClass {}
extension InternetPassword: PasswordItemClass {}

extension Attributes where Class: PasswordItemClass {
    /// `kSecAttrAccount`: the account name. Part of the primary key.
    public var account: String? {
        get { storage[.account]?.string }
        set { storage[.account] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrDescription`: a user-visible description of the item.
    public var itemDescription: String? {
        get { storage[.description]?.string }
        set { storage[.description] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrComment`: a user-editable comment.
    public var comment: String? {
        get { storage[.comment]?.string }
        set { storage[.comment] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrCreator`: the creating application, as a four-character code.
    public var creator: UInt32? {
        get { storage[.creator]?.fourCharacterCode }
        set { storage[.creator] = newValue.map { SecValue(fourCharacterCode: $0) } }
    }

    /// `kSecAttrType`: the item's type, as a four-character code.
    public var type: UInt32? {
        get { storage[.type]?.fourCharacterCode }
        set { storage[.type] = newValue.map { SecValue(fourCharacterCode: $0) } }
    }

    /// `kSecAttrIsInvisible`: hidden from keychain-browsing user interfaces.
    public var isInvisible: Bool? {
        get { storage[.isInvisible]?.bool }
        set { storage[.isInvisible] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrIsNegative`: a placeholder whose password lives elsewhere.
    public var isNegative: Bool? {
        get { storage[.isNegative]?.bool }
        set { storage[.isNegative] = newValue.map(SecValue.bool) }
    }
}
