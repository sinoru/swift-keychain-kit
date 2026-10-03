//
//  KeychainBackend.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The four SecItem operations, over `SecDictionary` instead of `CFDictionary`.
///
/// `SecurityBackend` implements this against the real framework. Test code implements it in
/// memory so that unit tests never reach a keychain. Everything above this protocol is pure
/// Swift and is tested through the in-memory implementation.
package protocol KeychainBackend: Sendable {
    /// `SecItemAdd`. Returns whatever the `kSecReturn*` keys in `attributes` asked for,
    /// which is nothing in the common case, hence the discardable result.
    @discardableResult
    func add(_ attributes: SecDictionary) throws(KeychainError) -> SecValue?

    /// `SecItemCopyMatching`. Returns whatever the `kSecReturn*` keys in `query` asked for.
    func copyMatching(_ query: SecDictionary) throws(KeychainError) -> SecValue?

    /// `SecItemUpdate`. Applies `attributes` to every item matching `query`.
    func update(_ query: SecDictionary, with attributes: SecDictionary) throws(KeychainError)

    /// `SecItemDelete`. Removes every item matching `query`.
    func delete(_ query: SecDictionary) throws(KeychainError)
}
