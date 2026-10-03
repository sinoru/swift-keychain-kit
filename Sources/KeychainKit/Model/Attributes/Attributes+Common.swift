//
//  Attributes+Common.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

// Attributes every item class has. Each property maps one `kSecAttr*` key to a Swift type.
// Properties the framework sets are read-only.

extension Attributes {
    /// `kSecAttrLabel`: the user-visible label.
    public var label: String? {
        get { value(Keys.label, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.label) }
    }

    /// `kSecAttrAccessGroup`: the single access group the item belongs to.
    /// 
    /// Omit it to use the app's default group. On macOS it applies only to the data
    /// protection keychain.
    public var accessGroup: AccessGroup? {
        get { value(Keys.accessGroup, as: { $0.constant() }) }
        set { setValue(newValue.map { SecValue(constant: $0) }, for: Keys.accessGroup) }
    }

    /// `kSecAttrSynchronizable`: whether the item syncs through iCloud Keychain.
    /// 
    /// Synchronizable items cannot use a `ThisDeviceOnly` accessibility. In a `Query`, the
    /// `synchronizable` property of the query takes precedence over this attribute.
    public var synchronizable: Bool? {
        get { value(Keys.synchronizable, as: \.bool) }
        set { setValue(newValue.map(SecValue.bool), for: Keys.synchronizable) }
    }

    /// `kSecAttrCreationDate`: when the item was added. Set by the framework.
    public var creationDate: Date? {
        value(Keys.creationDate, as: \.date)
    }

    /// `kSecAttrModificationDate`: when the item was last updated. Set by the framework.
    public var modificationDate: Date? {
        value(Keys.modificationDate, as: \.date)
    }
}

/// File-scoped because a type nested in a generic struct cannot hold static stored properties.
private enum Keys {
    static let label = kSecAttrLabel as String
    static let accessGroup = kSecAttrAccessGroup as String
    static let synchronizable = kSecAttrSynchronizable as String
    static let creationDate = kSecAttrCreationDate as String
    static let modificationDate = kSecAttrModificationDate as String
}
