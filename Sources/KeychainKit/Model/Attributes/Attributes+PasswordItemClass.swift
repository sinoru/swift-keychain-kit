//
//  Attributes+PasswordItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The two password classes share most of their attributes.
public protocol PasswordItemClass: ItemClass {}

extension GenericPassword: PasswordItemClass {}
extension InternetPassword: PasswordItemClass {}

extension Attributes where Class: PasswordItemClass {
    /// `kSecAttrAccount`: the account name. Part of the primary key.
    public var account: String? {
        get { storage[Keys.account]?.string }
        set { storage[Keys.account] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrDescription`: a user-visible description of the item.
    public var itemDescription: String? {
        get { storage[Keys.description]?.string }
        set { storage[Keys.description] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrComment`: a user-editable comment.
    public var comment: String? {
        get { storage[Keys.comment]?.string }
        set { storage[Keys.comment] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrCreator`: the creating application, as a four-character code.
    public var creator: UInt32? {
        get { storage[Keys.creator]?.fourCharacterCode }
        set { storage[Keys.creator] = newValue.map { SecValue(fourCharacterCode: $0) } }
    }

    /// `kSecAttrType`: the item's type, as a four-character code.
    public var type: UInt32? {
        get { storage[Keys.type]?.fourCharacterCode }
        set { storage[Keys.type] = newValue.map { SecValue(fourCharacterCode: $0) } }
    }

    /// `kSecAttrIsInvisible`: hidden from keychain-browsing user interfaces.
    public var isInvisible: Bool? {
        get { storage[Keys.isInvisible]?.bool }
        set { storage[Keys.isInvisible] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrIsNegative`: a placeholder whose password lives elsewhere.
    public var isNegative: Bool? {
        get { storage[Keys.isNegative]?.bool }
        set { storage[Keys.isNegative] = newValue.map(SecValue.bool) }
    }
}

/// File-scoped because a type nested in a generic struct cannot hold static stored properties.
private enum Keys {
    static let account = kSecAttrAccount as String
    static let description = kSecAttrDescription as String
    static let comment = kSecAttrComment as String
    static let creator = kSecAttrCreator as String
    static let type = kSecAttrType as String
    static let isInvisible = kSecAttrIsInvisible as String
    static let isNegative = kSecAttrIsNegative as String
}
