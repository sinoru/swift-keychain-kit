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

/// Runs the public `Keychain` API against the real framework and a temporary file-based keychain.
///
/// Each test owns its keychain, so the suite can run in parallel with everything else, and
/// nothing touches the login keychain.
@Suite struct KeychainIntegrationTests {
    private func withKeychain(_ body: (Keychain) throws -> Void) throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        try body(Keychain(storage: .fileBased(temporary.fileKeychain)))
    }

    private static let service = "dev.sinoru.KeychainKit.tests"

    private func item(account: String, data: String) -> Item<GenericPassword> {
        Item(service: Self.service, account: account, password: data)
    }

    private func query(account: String? = nil) -> Query<GenericPassword> {
        Query(service: Self.service, account: account)
    }

    // MARK: Add and read one

    @Test func addReturnsTheReferenceASearchFinds() throws {
        try withKeychain { keychain in
            let reference = try keychain.add(item(account: "one", data: "secret"))
            #expect(!reference.rawValue.isEmpty)
            #expect(try keychain.fetchFirstPersistentReference(matching: query(account: "one")) == reference)
        }
    }

    @Test func addRejectsDuplicates() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "secret"))
            #expect(throws: KeychainError(code: .duplicateItem)) {
                try keychain.add(item(account: "one", data: "again"))
            }
        }
    }

    @Test func firstReturnsAttributesAndData() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "secret"))
            let found = try #require(try keychain.fetchFirst(matching: query(account: "one")))
            #expect(found.service == Self.service)
            #expect(found.account == "one")
            #expect(found.password == "secret")
            #expect(found.creationDate != nil)
            #expect(found.modificationDate != nil)
        }
    }

    @Test func booleanAttributesRoundTripThroughTheFramework() throws {
        try withKeychain { keychain in
            var item = item(account: "one", data: "secret")
            item.isInvisible = true
            item.isNegative = false
            try keychain.add(item)
            let found = try #require(try keychain.fetchFirst(matching: query(account: "one")))
            #expect(found.isInvisible == true)
            #expect(found.isNegative == false)
        }
    }

    @Test func attributesReturnNoData() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "secret"))
            let attributes = try #require(try keychain.fetchFirstAttributes(matching: query(account: "one")))
            #expect(attributes.account == "one")
            #expect(try keychain.fetchFirstData(matching: query(account: "one")) == Data("secret".utf8))
        }
    }

    @Test func readsReturnNilWhenNothingMatches() throws {
        // The explicit signature matters: a closure whose only `try`s sit inside `#expect`
        // is not inferred as throwing, because the macro moves them into nested closures.
        try withKeychain { (keychain: Keychain) throws in
            #expect(try keychain.fetchFirst(matching: query()) == nil)
            #expect(try keychain.fetchFirstAttributes(matching: query()) == nil)
            #expect(try keychain.fetchFirstData(matching: query()) == nil)
            #expect(try keychain.fetchFirstPersistentReference(matching: query()) == nil)
            #expect(try keychain.fetch(matching: query()).isEmpty)
            #expect(try keychain.fetchAttributes(matching: query()).isEmpty)
            #expect(try keychain.fetchPersistentReferences(matching: query()).isEmpty)
        }
    }

    @Test func findsAnItemByPersistentReference() throws {
        try withKeychain { keychain in
            let reference = try keychain.add(item(account: "one", data: "secret"))
            try keychain.add(item(account: "two", data: "other"))
            var byReference = query()
            byReference.persistentReference = reference
            let found = try #require(try keychain.fetchFirst(matching: byReference))
            #expect(found.account == "one")
            #expect(found.password == "secret")
        }
    }

    // MARK: Read many

    @Test func allReturnsDataForEveryItem() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "1"))
            try keychain.add(item(account: "two", data: "2"))
            let items = try keychain.fetch(matching: query())
            #expect(Set(items.compactMap { $0.account }) == ["one", "two"])
            #expect(Set(items.compactMap(\.password)) == ["1", "2"])
            #expect(try keychain.fetchAttributes(matching: query()).count == 2)
            #expect(try keychain.fetchPersistentReferences(matching: query()).count == 2)
        }
    }

    // MARK: Update and delete

    @Test func updateAppliesOnlyTheChangesGiven() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "secret"))
            var changes = Item<GenericPassword>()
            changes.password = "changed"
            changes.comment = "comment"
            try keychain.update(matching: query(account: "one"), with: changes)

            let updated = try #require(try keychain.fetchFirst(matching: query(account: "one")))
            #expect(updated.password == "changed")
            #expect(updated.comment == "comment")
            #expect(updated.account == "one")
        }
    }

    @Test func updateAppliesToEveryMatch() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "1"))
            try keychain.add(item(account: "two", data: "2"))
            var changes = Item<GenericPassword>()
            changes.comment = "shared"
            try keychain.update(matching: query(), with: changes)
            let comments = try keychain.fetchAttributes(matching: query()).compactMap { $0.comment }
            #expect(comments == ["shared", "shared"])
        }
    }

    @Test func fetchesAcceptSkippingProtectedItems() throws {
        // The file-based keychain ignores the skip option, so this guards the request shape,
        // including the per-item data fetch behind `fetch(matching:)`.
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "1"))
            let one = query(account: "one")
            #expect(try keychain.fetchFirstData(matching: one, skippingItemsRequiringAuthentication: true) == Data("1".utf8))
            #expect(try keychain.fetch(matching: one, skippingItemsRequiringAuthentication: true).count == 1)
        }
    }

    @Test func updateThrowsWhenNothingMatches() throws {
        try withKeychain { keychain in
            #expect(throws: KeychainError(code: .itemNotFound)) {
                try keychain.update(matching: query(account: "missing"), with: Item(data: Data()))
            }
        }
    }

    @Test func deleteRemovesEveryMatchAndIsIdempotent() throws {
        try withKeychain { keychain in
            try keychain.add(item(account: "one", data: "1"))
            try keychain.add(item(account: "two", data: "2"))
            try keychain.delete(matching: query())
            #expect(try keychain.fetch(matching: query()).isEmpty)
            try keychain.delete(matching: query())
        }
    }

    // MARK: Asynchronous forms

    @Test func everyOperationHasAnAsynchronousForm() async throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))
        do {
            let reference = try await keychain.add(item(account: "one", data: "secret"))
            try await keychain.add(item(account: "two", data: "other"))

            #expect(try await keychain.fetchFirst(matching: query(account: "one"))?.password == "secret")
            #expect(try await keychain.fetchFirstAttributes(matching: query(account: "one"))?.account == "one")
            #expect(try await keychain.fetchFirstData(matching: query(account: "one")) == Data("secret".utf8))
            #expect(try await keychain.fetchFirstPersistentReference(matching: query(account: "one")) == reference)
            #expect(try await keychain.fetch(matching: query()).count == 2)
            #expect(try await keychain.fetchAttributes(matching: query()).count == 2)
            #expect(try await keychain.fetchPersistentReferences(matching: query()).count == 2)

            try await keychain.update(matching: query(account: "one"), with: Item(data: Data("changed".utf8)))
            #expect(try await keychain.fetchFirstData(matching: query(account: "one")) == Data("changed".utf8))

            try await keychain.delete(matching: query())
            #expect(try await keychain.fetch(matching: query()).isEmpty)

            await #expect(throws: KeychainError(code: .itemNotFound)) {
                try await keychain.update(matching: query(account: "missing"), with: Item(data: Data()))
            }
        }
    }

    @Test func concurrentCallsShareOneKeychainSafely() async throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for index in 0..<20 {
                    group.addTask {
                        try await keychain.add(item(account: "account-\(index)", data: "\(index)"))
                        _ = try await keychain.fetchFirst(matching: query(account: "account-\(index)"))
                    }
                }
                try await group.waitForAll()
            }
            let items = try await keychain.fetch(matching: query())
            #expect(items.count == 20)
            #expect(Set(items.compactMap(\.password)).count == 20)
        }
    }
}
#endif
