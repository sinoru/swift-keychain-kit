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
        get { value(Keys.account, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.account) }
    }

    /// `kSecAttrDescription`: a user-visible description of the item.
    public var description: String? {
        get { value(Keys.description, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.description) }
    }

    /// `kSecAttrComment`: a user-editable comment.
    public var comment: String? {
        get { value(Keys.comment, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.comment) }
    }

    /// `kSecAttrCreator`: the creating application, as a four-character code.
    public var creator: UInt32? {
        get { value(Keys.creator, as: \.fourCharacterCode) }
        set { setValue(newValue.map { SecValue(fourCharacterCode: $0) }, for: Keys.creator) }
    }

    /// `kSecAttrType`: the item's type, as a four-character code.
    public var type: UInt32? {
        get { value(Keys.type, as: \.fourCharacterCode) }
        set { setValue(newValue.map { SecValue(fourCharacterCode: $0) }, for: Keys.type) }
    }

    /// `kSecAttrIsInvisible`: hidden from keychain-browsing user interfaces.
    public var isInvisible: Bool? {
        get { value(Keys.isInvisible, as: \.bool) }
        set { setValue(newValue.map(SecValue.bool), for: Keys.isInvisible) }
    }

    /// `kSecAttrIsNegative`: a placeholder whose password lives elsewhere.
    public var isNegative: Bool? {
        get { value(Keys.isNegative, as: \.bool) }
        set { setValue(newValue.map(SecValue.bool), for: Keys.isNegative) }
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
