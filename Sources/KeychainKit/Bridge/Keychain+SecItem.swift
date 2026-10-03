//
//  Keychain+SecItem.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The four SecItem calls, over `SecDictionary` instead of `CFDictionary`.
///
/// This is the only place in the library that calls `SecItemAdd`, `SecItemCopyMatching`,
/// `SecItemUpdate`, or `SecItemDelete`. Those functions take an out-pointer for their result,
/// which strict memory safety classifies as unsafe, so the `unsafe` markers live here and
/// nowhere else. Everything above is pure Swift over `SecValue` and is tested without a
/// keychain; this layer is tested against a temporary keychain on macOS.
extension Keychain {
    /// `SecItemAdd`. Returns whatever the `kSecReturn*` keys in `attributes` asked for,
    /// which is nothing in the common case, hence the discardable result.
    @discardableResult
    package static func secItemAdd(_ attributes: SecDictionary) throws(KeychainError) -> SecValue? {
        var result: CFTypeRef?
        let status = unsafe SecItemAdd(attributes.cfDictionary, &result)
        try check(status)
        return result.map(SecValue.init(cf:))
    }

    /// `SecItemCopyMatching`. Returns whatever the `kSecReturn*` keys in `query` asked for.
    package static func secItemCopyMatching(_ query: SecDictionary) throws(KeychainError) -> SecValue? {
        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(query.cfDictionary, &result)
        try check(status)
        return result.map(SecValue.init(cf:))
    }

    /// `SecItemUpdate`. Applies `attributes` to every item matching `query`.
    package static func secItemUpdate(_ query: SecDictionary, with attributes: SecDictionary) throws(KeychainError) {
        try check(SecItemUpdate(query.cfDictionary, attributes.cfDictionary))
    }

    /// `SecItemDelete`. Removes every item matching `query`.
    package static func secItemDelete(_ query: SecDictionary) throws(KeychainError) {
        try check(SecItemDelete(query.cfDictionary))
    }
}
