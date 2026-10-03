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
        get { storage[Keys.label]?.string }
        set { storage[Keys.label] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrAccessGroup`: the single access group the item belongs to.
    /// 
    /// Omit it to use the app's default group. On macOS it applies only to the data
    /// protection keychain.
    public var accessGroup: AccessGroup? {
        get { storage[Keys.accessGroup]?.constant() }
        set { storage[Keys.accessGroup] = newValue.map { SecValue(constant: $0) } }
    }

    /// `kSecAttrSynchronizable`: whether the item syncs through iCloud Keychain.
    /// 
    /// Synchronizable items cannot use a `ThisDeviceOnly` accessibility. In a `Query`, the
    /// `synchronizable` property of the query takes precedence over this attribute.
    public var synchronizable: Bool? {
        get { storage[Keys.synchronizable]?.bool }
        set { storage[Keys.synchronizable] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCreationDate`: when the item was added. Set by the framework.
    public var creationDate: Date? {
        storage[Keys.creationDate]?.date
    }

    /// `kSecAttrModificationDate`: when the item was last updated. Set by the framework.
    public var modificationDate: Date? {
        storage[Keys.modificationDate]?.date
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
