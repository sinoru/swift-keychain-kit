//
//  Attributes+GenericPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

extension Attributes where Class == GenericPassword {
    /// `kSecAttrService`: the service the password is for. Part of the primary key.
    public var service: String? {
        get { storage[Keys.service]?.string }
        set { storage[Keys.service] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrGeneric`: arbitrary user-defined data that is not part of the primary key.
    public var generic: Data? {
        get { storage[Keys.generic]?.data }
        set { storage[Keys.generic] = newValue.map(SecValue.data) }
    }
}

/// File-scoped because a type nested in a generic struct cannot hold static stored properties.
private enum Keys {
    static let service = kSecAttrService as String
    static let generic = kSecAttrGeneric as String
}
