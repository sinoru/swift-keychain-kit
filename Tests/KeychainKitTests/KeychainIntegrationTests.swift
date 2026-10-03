//
//  KeychainIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
import Foundation
import Security
import Testing

import KeychainKit
import KeychainKitTestSupport

/// Runs the public `Keychain` API against the real framework and a temporary file-based keychain.
@Suite struct KeychainIntegrationTests {
    private func withKeychain(_ body: (Keychain) throws -> Void) throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        try body(Keychain(storage: .fileBased(temporary.fileKeychain)))
    }

    private func item(account: String, data: String) -> Item<GenericPassword> {
        var item = Item<GenericPassword>(data: Data(data.utf8))
        item[.service] = "dev.sinoru.KeychainKit.tests"
        item[.account] = account
        return item
    }

    private var query: Query<GenericPassword> {
        var query = Query<GenericPassword>()
        query[.service] = "dev.sinoru.KeychainKit.tests"
        return query
    }

    @Test func roundTripsAnItem() throws {
        try withKeychain { keychain in
            let reference = try keychain.add(item(account: "one", data: "secret"))
            var byAccount = query
            byAccount[.account] = "one"

            let found = try #require(try keychain.first(matching: byAccount))
            #expect(found[.account] == "one")
            #expect(found.data == Data("secret".utf8))
            #expect(found[.creationDate] != nil)
            #expect(try keychain.persistentReference(matching: byAccount) == reference)
        }
    }

    @Test func findsAnItemByPersistentReference() throws {
        try withKeychain { keychain in
            let reference = try keychain.add(item(account: "one", data: "secret"))
            try keychain.add(item(account: "two", data: "other"))

            var byReference = query
            byReference.persistentReference = reference
            let found = try #require(try keychain.first(matching: byReference))
            #expect(found[.account] == "one")
            #expect(found.data == Data("secret".utf8))
        }
    }

    @Test func allReturnsDataForEveryItem() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "1"))
            try keychain.add(item(account: "two", data: "2"))
            let items = try keychain.all(matching: query)
            #expect(Set(items.compactMap { $0[.account] }) == ["one", "two"])
            #expect(Set(items.compactMap(\.data)) == [Data("1".utf8), Data("2".utf8)])
            #expect(try keychain.allAttributes(matching: query).count == 2)
        }
    }

    @Test func updatesAndDeletes() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "secret"))
            var byAccount = query
            byAccount[.account] = "one"

            var changes = Item<GenericPassword>(data: Data("changed".utf8))
            changes[.comment] = "comment"
            try keychain.update(matching: byAccount, with: changes)
            let updated = try #require(try keychain.first(matching: byAccount))
            #expect(updated.data == Data("changed".utf8))
            #expect(updated[.comment] == "comment")

            try keychain.delete(matching: byAccount)
            #expect(try keychain.first(matching: byAccount) == nil)
            try keychain.delete(matching: byAccount)
        }
    }

    @Test func reportsNotFoundAsNilAndDuplicatesAsErrors() throws {
        try withKeychain { keychain in
            #expect(try keychain.first(matching: query) == nil)
            #expect(try keychain.all(matching: query).isEmpty)
            try keychain.add(item(account: "one", data: "secret"))
            #expect(throws: KeychainError(code: .duplicateItem)) {
                try keychain.add(item(account: "one", data: "again"))
            }
            #expect(throws: KeychainError(code: .itemNotFound)) {
                var missing = query
                missing[.account] = "missing"
                try keychain.update(matching: missing, with: Item(data: Data()))
            }
        }
    }
}
#endif
