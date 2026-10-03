//
//  Query+Common.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

// Every writable attribute of `attributes` is reachable directly on the query, so `query.label` and
// `query.attributes.label` are the same thing. Written out rather than provided through
// `@dynamicMemberLookup` for the reason given in `Item+Common.swift`.
// The framework-set dates are omitted because they cannot be set as match criteria, and
// `synchronizable` is omitted because the query's own `synchronizable` match mode replaces it.

extension Query {
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
}
