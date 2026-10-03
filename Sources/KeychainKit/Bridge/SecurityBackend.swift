//
//  SecurityBackend.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The `KeychainBackend` that talks to the Security framework.
///
/// This is the only type in the library that calls `SecItemAdd`, `SecItemCopyMatching`,
/// `SecItemUpdate`, or `SecItemDelete`. Those functions take an out-pointer for their result,
/// which strict memory safety classifies as unsafe, so the `unsafe` markers live here and
/// nowhere else.
package struct SecurityBackend: KeychainBackend {
    package init() {}

    @discardableResult
    package func add(_ attributes: SecDictionary) throws(KeychainError) -> SecValue? {
        var result: CFTypeRef?
        let status = unsafe SecItemAdd(attributes.cfDictionary, &result)
        try check(status)
        return result.map(SecValue.init(cf:))
    }

    package func copyMatching(_ query: SecDictionary) throws(KeychainError) -> SecValue? {
        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(query.cfDictionary, &result)
        try check(status)
        return result.map(SecValue.init(cf:))
    }

    package func update(_ query: SecDictionary, with attributes: SecDictionary) throws(KeychainError) {
        try check(SecItemUpdate(query.cfDictionary, attributes.cfDictionary))
    }

    package func delete(_ query: SecDictionary) throws(KeychainError) {
        try check(SecItemDelete(query.cfDictionary))
    }
}
