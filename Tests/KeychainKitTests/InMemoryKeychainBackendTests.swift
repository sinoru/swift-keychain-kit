//
//  InMemoryKeychainBackendTests.swift
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

@Suite struct InMemoryKeychainBackendTests {
    private let backend = InMemoryKeychainBackend()

    private func genericPassword(
        service: String = "service",
        account: String = "account",
        data: Data? = Data("secret".utf8),
        extra: SecDictionary = [:],
    ) -> SecDictionary {
        var attributes: SecDictionary = [
            kSecClass as String: .string(kSecClassGenericPassword as String),
            kSecAttrService as String: .string(service),
            kSecAttrAccount as String: .string(account),
        ]
        if let data {
            attributes[kSecValueData as String] = .data(data)
        }
        return attributes.merging(extra) { _, new in new }
    }

    private func query(service: String = "service", account: String? = "account", extra: SecDictionary = [:]) -> SecDictionary {
        var query: SecDictionary = [
            kSecClass as String: .string(kSecClassGenericPassword as String),
            kSecAttrService as String: .string(service),
        ]
        if let account {
            query[kSecAttrAccount as String] = .string(account)
        }
        return query.merging(extra) { _, new in new }
    }

    // MARK: Add

    @Test func addStoresItemAndReturnsNothingWithoutReturnKeys() throws {
        let result = try backend.add(genericPassword())
        #expect(result == nil)
        #expect(backend.itemCount == 1)
    }

    @Test func addHonorsReturnKeys() throws {
        let result = try backend.add(genericPassword(extra: [kSecReturnPersistentRef as String: .bool(true)]))
        guard case .data(let reference)? = result else {
            Issue.record("expected a persistent reference, got \(String(describing: result))")
            return
        }
        #expect(!reference.isEmpty)
    }

    @Test func addRejectsDuplicatePrimaryKey() throws {
        try backend.add(genericPassword())
        #expect(throws: KeychainError(code: .duplicateItem)) {
            try backend.add(genericPassword(data: Data("other".utf8)))
        }
        #expect(backend.itemCount == 1)
    }

    @Test func addAllowsSameServiceWithDifferentAccount() throws {
        try backend.add(genericPassword(account: "one"))
        try backend.add(genericPassword(account: "two"))
        #expect(backend.itemCount == 2)
    }

    @Test func addRequiresItemClass() {
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try backend.add([kSecAttrService as String: .string("service")])
        }
    }

    @Test func addRecordsCreationAndModificationDates() throws {
        let created = Date(timeIntervalSince1970: 1_000)
        let backend = InMemoryKeychainBackend(now: { created })
        try backend.add(genericPassword())
        let attributes = try #require(try backend.copyMatching(query(extra: [kSecReturnAttributes as String: .bool(true)])))
        #expect(attributes == .dictionary([
            kSecClass as String: .string("genp"),
            kSecAttrService as String: .string("service"),
            kSecAttrAccount as String: .string("account"),
            kSecAttrCreationDate as String: .date(created),
            kSecAttrModificationDate as String: .date(created),
        ]))
    }

    // MARK: Copy

    @Test func copyReturnsBareDataForSingleReturnKey() throws {
        try backend.add(genericPassword())
        let result = try backend.copyMatching(query(extra: [kSecReturnData as String: .bool(true)]))
        #expect(result == .data(Data("secret".utf8)))
    }

    @Test func copyReturnsDictionaryForSeveralReturnKeys() throws {
        try backend.add(genericPassword())
        let result = try backend.copyMatching(query(extra: [
            kSecReturnData as String: .bool(true),
            kSecReturnAttributes as String: .bool(true),
        ]))
        guard case .dictionary(let dictionary)? = result else {
            Issue.record("expected a dictionary, got \(String(describing: result))")
            return
        }
        #expect(dictionary[kSecValueData as String] == .data(Data("secret".utf8)))
        #expect(dictionary[kSecAttrService as String] == .string("service"))
        #expect(dictionary[kSecClass as String] == .string("genp"))
    }

    @Test func copyReturnsNothingWithoutReturnKeys() throws {
        try backend.add(genericPassword())
        #expect(try backend.copyMatching(query()) == nil)
    }

    @Test func copyThrowsWhenNothingMatches() throws {
        try backend.add(genericPassword())
        #expect(throws: KeychainError(code: .itemNotFound)) {
            try backend.copyMatching(query(account: "missing"))
        }
    }

    @Test func copyMatchesAllAttributesInQueryButIgnoresUseKeys() throws {
        try backend.add(genericPassword(extra: [kSecAttrLabel as String: .string("label")]))
        let query = query(extra: [
            kSecAttrLabel as String: .string("label"),
            kSecUseDataProtectionKeychain as String: .bool(true),
            kSecReturnData as String: .bool(true),
        ])
        #expect(try backend.copyMatching(query) == .data(Data("secret".utf8)))
    }

    @Test func copyWithLimitAllReturnsArray() throws {
        try backend.add(genericPassword(account: "one"))
        try backend.add(genericPassword(account: "two"))
        let result = try backend.copyMatching(query(account: nil, extra: [
            kSecMatchLimit as String: .string(kSecMatchLimitAll as String),
            kSecReturnAttributes as String: .bool(true),
        ]))
        guard case .array(let items)? = result else {
            Issue.record("expected an array, got \(String(describing: result))")
            return
        }
        #expect(items.count == 2)
    }

    @Test func copyWithLimitOneReturnsBareValueEvenWhenSeveralMatch() throws {
        try backend.add(genericPassword(account: "one"))
        try backend.add(genericPassword(account: "two"))
        let result = try backend.copyMatching(query(account: nil, extra: [kSecReturnAttributes as String: .bool(true)]))
        guard case .dictionary? = result else {
            Issue.record("expected a dictionary, got \(String(describing: result))")
            return
        }
    }

    @Test func copyHidesSynchronizableItemsUnlessAsked() throws {
        try backend.add(genericPassword(account: "local"))
        try backend.add(genericPassword(account: "cloud", extra: [kSecAttrSynchronizable as String: .bool(true)]))

        let all = query(account: nil, extra: [kSecMatchLimit as String: .string(kSecMatchLimitAll as String), kSecReturnAttributes as String: .bool(true)])
        #expect(try count(backend.copyMatching(all)) == 1)
        #expect(try count(backend.copyMatching(all.merging([kSecAttrSynchronizable as String: .bool(true)]) { _, new in new })) == 1)
        #expect(try count(backend.copyMatching(all.merging([kSecAttrSynchronizable as String: .string(kSecAttrSynchronizableAny as String)]) { _, new in new })) == 2)
    }

    @Test func copyFiltersByAccessGroup() throws {
        try backend.add(genericPassword(extra: [kSecAttrAccessGroup as String: .string("TEAM.shared")]))
        #expect(throws: KeychainError(code: .itemNotFound)) {
            try backend.copyMatching(query(extra: [kSecAttrAccessGroup as String: .string("TEAM.other")]))
        }
        #expect(try backend.copyMatching(query(extra: [kSecAttrAccessGroup as String: .string("TEAM.shared"), kSecReturnData as String: .bool(true)])) == .data(Data("secret".utf8)))
    }

    @Test func persistentReferenceFindsItsItem() throws {
        try backend.add(genericPassword(account: "one"))
        try backend.add(genericPassword(account: "two"))
        let reference = try backend.copyMatching(query(account: "two", extra: [kSecReturnPersistentRef as String: .bool(true)]))
        guard case .data(let referenceData)? = reference else {
            Issue.record("expected a persistent reference, got \(String(describing: reference))")
            return
        }
        let found = try backend.copyMatching([
            kSecClass as String: .string(kSecClassGenericPassword as String),
            kSecValuePersistentRef as String: .data(referenceData),
            kSecReturnAttributes as String: .bool(true),
        ])
        guard case .dictionary(let attributes)? = found else {
            Issue.record("expected attributes, got \(String(describing: found))")
            return
        }
        #expect(attributes[kSecAttrAccount as String] == .string("two"))
    }

    // MARK: Update

    @Test func updateReplacesDataAndTouchesModificationDate() throws {
        let created = Date(timeIntervalSince1970: 1_000)
        let modified = Date(timeIntervalSince1970: 2_000)
        let clock = Clock(created)
        let backend = InMemoryKeychainBackend(now: { clock.now })
        try backend.add(genericPassword())

        clock.now = modified
        try backend.update(query(), with: [kSecValueData as String: .data(Data("changed".utf8))])

        let result = try backend.copyMatching(query(extra: [kSecReturnData as String: .bool(true), kSecReturnAttributes as String: .bool(true)]))
        guard case .dictionary(let dictionary)? = result else {
            Issue.record("expected a dictionary, got \(String(describing: result))")
            return
        }
        #expect(dictionary[kSecValueData as String] == .data(Data("changed".utf8)))
        #expect(dictionary[kSecAttrCreationDate as String] == .date(created))
        #expect(dictionary[kSecAttrModificationDate as String] == .date(modified))
    }

    @Test func updateThrowsWhenNothingMatches() {
        #expect(throws: KeychainError(code: .itemNotFound)) {
            try backend.update(query(), with: [kSecValueData as String: .data(Data())])
        }
    }

    @Test func updateRejectsPrimaryKeyCollision() throws {
        try backend.add(genericPassword(account: "one"))
        try backend.add(genericPassword(account: "two"))
        #expect(throws: KeychainError(code: .duplicateItem)) {
            try backend.update(query(account: "one"), with: [kSecAttrAccount as String: .string("two")])
        }
        #expect(try backend.copyMatching(query(account: "one")) == nil)
    }

    // MARK: Delete

    @Test func deleteRemovesEveryMatchingItem() throws {
        try backend.add(genericPassword(account: "one"))
        try backend.add(genericPassword(account: "two"))
        try backend.add(genericPassword(service: "other"))
        try backend.delete(query(account: nil))
        #expect(backend.itemCount == 1)
    }

    @Test func deleteThrowsWhenNothingMatches() {
        #expect(throws: KeychainError(code: .itemNotFound)) {
            try backend.delete(query())
        }
    }

    // MARK: Internet password primary key

    @Test func internetPasswordsWithDifferentPortsCoexist() throws {
        func item(port: Int) -> SecDictionary {
            [
                kSecClass as String: .string(kSecClassInternetPassword as String),
                kSecAttrServer as String: .string("example.com"),
                kSecAttrAccount as String: .string("account"),
                kSecAttrPort as String: .number(port),
                kSecValueData as String: .data(Data("secret".utf8)),
            ]
        }
        try backend.add(item(port: 443))
        try backend.add(item(port: 8443))
        #expect(throws: KeychainError(code: .duplicateItem)) {
            try backend.add(item(port: 443))
        }
        #expect(backend.itemCount == 2)
    }

    // MARK: Helpers

    private func count(_ value: SecValue?) -> Int {
        if case .array(let items)? = value { items.count } else { 0 }
    }

    private final class Clock: @unchecked Sendable {
        var now: Date
        init(_ now: Date) { self.now = now }
    }
}
