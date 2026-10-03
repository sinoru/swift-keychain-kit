//
//  Attributes+GenericPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Attributes where Class == GenericPassword {
    /// `kSecAttrService`: the service the password is for. Part of the primary key.
    public var service: String? {
        get { storage[.service]?.string }
        set { storage[.service] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrGeneric`: arbitrary user-defined data that is not part of the primary key.
    public var generic: Data? {
        get { storage[.generic]?.data }
        set { storage[.generic] = newValue.map(SecValue.data) }
    }
}
