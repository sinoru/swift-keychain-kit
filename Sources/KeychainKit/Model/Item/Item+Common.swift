//
//  Item+Common.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

// Every attribute of `attributes` is reachable directly on the item, so `item.label` and
// `item.attributes.label` are the same thing. These are written out rather than provided through
// `@dynamicMemberLookup` because the key-path form survives optimization as a
// `swift_getAtKeyPath` call, while a plain forwarding property compiles to a direct call.

extension Item {
    /// Forwards to `Attributes/label`.
    public var label: String? {
        get { attributes.label }
        set { attributes.label = newValue }
    }

    /// Forwards to `Attributes/accessGroup`.
    public var accessGroup: AccessGroup? {
        get { attributes.accessGroup }
        set { attributes.accessGroup = newValue }
    }

    /// Forwards to `Attributes/synchronizable`.
    public var synchronizable: Bool? {
        get { attributes.synchronizable }
        set { attributes.synchronizable = newValue }
    }

    /// Forwards to `Attributes/creationDate`.
    public var creationDate: Date? {
        attributes.creationDate
    }

    /// Forwards to `Attributes/modificationDate`.
    public var modificationDate: Date? {
        attributes.modificationDate
    }
}
