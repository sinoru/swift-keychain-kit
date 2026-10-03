//
//  KeychainAsyncTests.swift
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

/// The asynchronous overloads must behave exactly like the synchronous ones.
@Suite struct KeychainAsyncTests {
    private let backend = InMemoryKeychainBackend()

    private var keychain: Keychain {
        Keychain(backend: backend, storage: .dataProtection, accessGroup: nil)
    }

    private func item(account: String, data: String = "secret") -> Item<GenericPassword> {
        var item = Item<GenericPassword>(data: Data(data.utf8))
        item[.service] = "service"
        item[.account] = account
        return item
    }

    private func query(account: String? = nil) -> Query<GenericPassword> {
        var query = Query<GenericPassword>()
        query[.service] = "service"
        query[.account] = account
        return query
    }

    @Test func everyOperationHasAnAsynchronousForm() async throws {
        let reference = try await keychain.add(item(account: "one"))
        try await keychain.add(item(account: "two"))

        #expect(try await keychain.first(matching: query(account: "one"))?.data == Data("secret".utf8))
        #expect(try await keychain.attributes(matching: query(account: "one"))?[.account] == "one")
        #expect(try await keychain.data(matching: query(account: "one")) == Data("secret".utf8))
        #expect(try await keychain.persistentReference(matching: query(account: "one")) == reference)
        #expect(try await keychain.all(matching: query()).count == 2)
        #expect(try await keychain.allAttributes(matching: query()).count == 2)
        #expect(try await keychain.allPersistentReferences(matching: query()).count == 2)

        try await keychain.update(matching: query(account: "one"), with: Item(data: Data("changed".utf8)))
        #expect(try await keychain.data(matching: query(account: "one")) == Data("changed".utf8))

        try await keychain.delete(matching: query())
        #expect(try await keychain.all(matching: query()).isEmpty)
        try await keychain.delete(matching: query())
    }

    @Test func asynchronousFormsPropagateErrors() async throws {
        try await keychain.add(item(account: "one"))
        await #expect(throws: KeychainError(code: .duplicateItem)) {
            try await keychain.add(item(account: "one"))
        }
        await #expect(throws: KeychainError(code: .itemNotFound)) {
            try await keychain.update(matching: query(account: "missing"), with: Item(data: Data()))
        }
    }

    @Test func concurrentCallsShareOneKeychainSafely() async throws {
        let keychain = keychain
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<50 {
                group.addTask {
                    try await keychain.add(item(account: "account-\(index)", data: "\(index)"))
                    _ = try await keychain.first(matching: query(account: "account-\(index)"))
                }
            }
            try await group.waitForAll()
        }
        let items = try await keychain.all(matching: query())
        #expect(items.count == 50)
        #expect(Set(items.compactMap(\.data)).count == 50)
    }
}
