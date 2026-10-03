//
//  KeychainTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit
import KeychainKitTestSupport

/// Exercises the `Keychain` operations end to end against the in-memory backend.
@Suite struct KeychainTests {
    private let backend = InMemoryKeychainBackend()

    private var keychain: Keychain {
        Keychain(backend: backend, storage: .dataProtection, accessGroup: nil)
    }

    private func item(account: String = "account", data: Data? = Data("secret".utf8)) -> Item<GenericPassword> {
        var item = Item<GenericPassword>(data: data)
        item[.service] = "service"
        item[.account] = account
        return item
    }

    private func query(account: String? = "account") -> Query<GenericPassword> {
        var query = Query<GenericPassword>()
        query[.service] = "service"
        query[.account] = account
        return query
    }

    // MARK: Add

    @Test func addReturnsAPersistentReference() throws {
        let reference = try keychain.add(item())
        #expect(!reference.rawValue.isEmpty)
        #expect(backend.itemCount == 1)
    }

    @Test func addRejectsDuplicates() throws {
        try keychain.add(item())
        #expect(throws: KeychainError(code: .duplicateItem)) {
            try keychain.add(item())
        }
    }

    // MARK: Read one

    @Test func firstReturnsAttributesAndData() throws {
        try keychain.add(item())
        let found = try #require(try keychain.first(matching: query()))
        #expect(found[.service] == "service")
        #expect(found[.account] == "account")
        #expect(found.data == Data("secret".utf8))
        #expect(found[.creationDate] != nil)
    }

    @Test func firstReturnsNilWhenNothingMatches() throws {
        #expect(try keychain.first(matching: query()) == nil)
    }

    @Test func attributesReturnsNoData() throws {
        try keychain.add(item())
        let attributes = try #require(try keychain.attributes(matching: query()))
        #expect(attributes[.account] == "account")
        #expect(attributes.storage[kSecValueData as String] == nil)
    }

    @Test func dataReturnsOnlyTheSecret() throws {
        try keychain.add(item())
        #expect(try keychain.data(matching: query()) == Data("secret".utf8))
        #expect(try keychain.data(matching: query(account: "missing")) == nil)
    }

    @Test func persistentReferenceMatchesTheOneReturnedByAdd() throws {
        let added = try keychain.add(item())
        #expect(try keychain.persistentReference(matching: query()) == added)
    }

    @Test func persistentReferenceFindsTheItemAgain() throws {
        let added = try keychain.add(item(account: "one"))
        try keychain.add(item(account: "two"))
        var query = Query<GenericPassword>()
        query.persistentReference = added
        #expect(try keychain.first(matching: query)?[.account] == "one")
    }

    // MARK: Read many

    @Test func allReturnsEveryItemWithData() throws {
        try keychain.add(item(account: "one", data: Data("1".utf8)))
        try keychain.add(item(account: "two", data: Data("2".utf8)))
        let items = try keychain.all(matching: query(account: nil))
        #expect(items.count == 2)
        #expect(Set(items.compactMap { $0[.account] }) == ["one", "two"])
        #expect(Set(items.compactMap(\.data)) == [Data("1".utf8), Data("2".utf8)])
    }

    @Test func allReturnsEmptyWhenNothingMatches() throws {
        #expect(try keychain.all(matching: query()).isEmpty)
        #expect(try keychain.allAttributes(matching: query()).isEmpty)
        #expect(try keychain.allPersistentReferences(matching: query()).isEmpty)
    }

    @Test func allAttributesAndAllPersistentReferencesAgreeWithAll() throws {
        try keychain.add(item(account: "one"))
        try keychain.add(item(account: "two"))
        let attributes = try keychain.allAttributes(matching: query(account: nil))
        let references = try keychain.allPersistentReferences(matching: query(account: nil))
        #expect(attributes.count == 2)
        #expect(references.count == 2)
        #expect(attributes.allSatisfy { $0.storage[kSecValueData as String] == nil })
    }

    @Test func allKeepsItemsInANonDefaultAccessGroup() throws {
        let shared = try #require(AccessGroup(rawValue: "TEAM.shared"))
        let keychain = Keychain(backend: backend, storage: .dataProtection, accessGroup: AccessGroup(rawValue: "TEAM.default"))
        var item = item()
        item[.accessGroup] = shared
        try keychain.add(item)

        var query = query()
        query[.accessGroup] = shared
        let items = try keychain.all(matching: query)
        #expect(items.count == 1)
        #expect(items.first?.data == Data("secret".utf8))
    }

    // MARK: Update

    @Test func updateAppliesOnlyTheChangesGiven() throws {
        try keychain.add(item())
        var changes = Item<GenericPassword>(data: Data("changed".utf8))
        changes[.label] = "label"
        try keychain.update(matching: query(), with: changes)

        let found = try #require(try keychain.first(matching: query()))
        #expect(found.data == Data("changed".utf8))
        #expect(found[.label] == "label")
        #expect(found[.account] == "account")
    }

    @Test func updateThrowsWhenNothingMatches() {
        #expect(throws: KeychainError(code: .itemNotFound)) {
            try keychain.update(matching: query(), with: Item(data: Data()))
        }
    }

    // MARK: Delete

    @Test func deleteRemovesMatchesAndIsIdempotent() throws {
        try keychain.add(item(account: "one"))
        try keychain.add(item(account: "two"))
        try keychain.delete(matching: query(account: nil))
        #expect(backend.itemCount == 0)
        try keychain.delete(matching: query(account: nil))
    }

    @Test func deletePropagatesOtherErrors() {
        let failing = RecordingKeychainBackend()
        failing.fail(with: KeychainError(code: .interactionNotAllowed))
        let keychain = Keychain(backend: failing, storage: .dataProtection, accessGroup: nil)
        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try keychain.delete(matching: query())
        }
    }

    // MARK: Item

    @Test func itemSubscriptsForwardToAttributes() {
        var item = Item<InternetPassword>()
        item[.server] = "example.com"
        item[.port] = 443
        #expect(item.attributes[.server] == "example.com")
        #expect(item[.port] == 443)
        #expect(item[.creationDate] == nil)
    }
}
