//
//  SecItemIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
import Foundation
import Security
import Testing

@testable import KeychainKit
import KeychainKitTestSupport

/// Runs the raw SecItem calls against a temporary file-based keychain.
///
/// Each test owns its keychain, so the suite can run in parallel with everything else. The
/// keychain lives in the temporary directory and is deleted at the end of each test; nothing
/// touches the login keychain.
@Suite struct SecItemIntegrationTests {
    private func withTemporaryKeychain(_ body: (TemporaryFileKeychain) throws -> Void) throws {
        let keychain = try TemporaryFileKeychain()
        defer { try? keychain.tearDown() }
        try body(keychain)
    }

    private func genericPassword(in keychain: TemporaryFileKeychain, account: String = "account", data: Data = Data("secret".utf8)) -> SecDictionary {
        [
            kSecClass as String: .string(kSecClassGenericPassword as String),
            kSecAttrService as String: .string("dev.sinoru.KeychainKit.tests"),
            kSecAttrAccount as String: .string(account),
            kSecValueData as String: .data(data),
        ].merging(keychain.useKeychainEntry) { _, new in new }
    }

    private func query(in keychain: TemporaryFileKeychain, account: String = "account", extra: SecDictionary = [:]) -> SecDictionary {
        [
            kSecClass as String: .string(kSecClassGenericPassword as String),
            kSecAttrService as String: .string("dev.sinoru.KeychainKit.tests"),
            kSecAttrAccount as String: .string(account),
        ].merging(keychain.searchListEntry) { _, new in new }.merging(extra) { _, new in new }
    }

    @Test func addsAndReadsBackData() throws {
        try withTemporaryKeychain { keychain in
            try Keychain.secItemAdd(genericPassword(in: keychain))
            let result = try Keychain.secItemCopyMatching(query(in: keychain, extra: [kSecReturnData as String: .bool(true)]))
            #expect(result == .data(Data("secret".utf8)))
        }
    }

    @Test func rejectsDuplicates() throws {
        try withTemporaryKeychain { keychain in
            try Keychain.secItemAdd(genericPassword(in: keychain))
            #expect(throws: KeychainError(code: .duplicateItem)) {
                try Keychain.secItemAdd(genericPassword(in: keychain))
            }
        }
    }

    @Test func returnsAttributesAndDataTogether() throws {
        try withTemporaryKeychain { keychain in
            try Keychain.secItemAdd(genericPassword(in: keychain))
            let result = try Keychain.secItemCopyMatching(query(in: keychain, extra: [
                kSecReturnData as String: .bool(true),
                kSecReturnAttributes as String: .bool(true),
            ]))
            guard case .dictionary(let dictionary)? = result else {
                Issue.record("expected a dictionary, got \(String(describing: result))")
                return
            }
            #expect(dictionary[kSecValueData as String] == .data(Data("secret".utf8)))
            #expect(dictionary[kSecAttrAccount as String] == .string("account"))
            #expect(dictionary[kSecClass as String] == .string("genp"))
            #expect(dictionary[kSecAttrCreationDate as String] != nil)
        }
    }

    @Test func updatesData() throws {
        try withTemporaryKeychain { keychain in
            try Keychain.secItemAdd(genericPassword(in: keychain))
            try Keychain.secItemUpdate(query(in: keychain), with: [kSecValueData as String: .data(Data("changed".utf8))])
            let result = try Keychain.secItemCopyMatching(query(in: keychain, extra: [kSecReturnData as String: .bool(true)]))
            #expect(result == .data(Data("changed".utf8)))
        }
    }

    @Test func deletesAndThenReportsNotFound() throws {
        try withTemporaryKeychain { keychain in
            try Keychain.secItemAdd(genericPassword(in: keychain))
            try Keychain.secItemDelete(query(in: keychain))
            #expect(throws: KeychainError(code: .itemNotFound)) {
                try Keychain.secItemCopyMatching(query(in: keychain, extra: [kSecReturnData as String: .bool(true)]))
            }
        }
    }

    @Test func itemsStayOutOfTheDefaultSearchList() throws {
        try withTemporaryKeychain { keychain in
            let account = "isolated-\(UUID().uuidString)"
            try Keychain.secItemAdd(genericPassword(in: keychain, account: account))
            // The same account through the temporary keychain is found; through the default
            // search list it must not be.
            var query = query(in: keychain, account: account, extra: [kSecReturnAttributes as String: .bool(true)])
            #expect(try Keychain.secItemCopyMatching(query) != nil)
            query[kSecMatchSearchList as String] = nil
            #expect(throws: KeychainError(code: .itemNotFound)) {
                try Keychain.secItemCopyMatching(query)
            }
        }
    }
}
#endif
