//
//  KeychainDictionaryTests.swift
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

/// Checks the dictionaries a `Keychain` hands to its backend.
@Suite struct KeychainDictionaryTests {
    private let backend = RecordingKeychainBackend()

    private func keychain(storage: Storage = .dataProtection, accessGroup: AccessGroup? = nil) -> Keychain {
        Keychain(backend: backend, storage: storage, accessGroup: accessGroup)
    }

    private var query: Query<GenericPassword> {
        var query = Query<GenericPassword>()
        query[.service] = "service"
        return query
    }

    private var lastCall: RecordingKeychainBackend.Call? {
        backend.calls.last
    }

    @Test func dataProtectionStorageIsRequestedOnEveryCall() throws {
        backend.respond(with: .data(Data([1])))
        let keychain = keychain()
        try keychain.add(Item<GenericPassword>(data: Data()))
        backend.respond(with: nil)
        _ = try keychain.first(matching: query)
        try keychain.update(matching: query, with: Item(data: Data()))
        try keychain.delete(matching: query)
        #expect(backend.calls.count == 4)
        #expect(backend.calls.allSatisfy { $0.dictionary[kSecUseDataProtectionKeychain as String] == .bool(true) })
    }

    @Test func defaultAccessGroupIsInjectedUnlessNamed() throws {
        let keychain = keychain(accessGroup: AccessGroup(rawValue: "TEAM.default"))
        _ = try keychain.first(matching: query)
        #expect(lastCall?.dictionary[kSecAttrAccessGroup as String] == .string("TEAM.default"))

        var explicit = query
        explicit[.accessGroup] = AccessGroup(rawValue: "TEAM.other")
        _ = try keychain.first(matching: explicit)
        #expect(lastCall?.dictionary[kSecAttrAccessGroup as String] == .string("TEAM.other"))
    }

    @Test func addSendsClassDataAndAsksForAPersistentReference() throws {
        backend.respond(with: .data(Data([1])))
        var item = Item<InternetPassword>(data: Data("secret".utf8))
        item[.server] = "example.com"
        try keychain().add(item)
        let dictionary = try #require(lastCall?.dictionary)
        #expect(lastCall?.operation == .add)
        #expect(dictionary[kSecClass as String] == .string(kSecClassInternetPassword as String))
        #expect(dictionary[kSecAttrServer as String] == .string("example.com"))
        #expect(dictionary[kSecValueData as String] == .data(Data("secret".utf8)))
        #expect(dictionary[kSecReturnPersistentRef as String] == .bool(true))
        #expect(dictionary[kSecReturnData as String] == nil)
    }

    @Test func addFailsToDecodeAnUnexpectedResult() {
        backend.respond(with: .bool(true))
        #expect(throws: KeychainError(code: .decodingFailed)) {
            try keychain().add(Item<GenericPassword>(data: Data()))
        }
    }

    @Test func readOperationsRequestTheRightReturnKeys() throws {
        let keychain = keychain()
        func returnKeys(_ dictionary: SecDictionary) -> Set<String> {
            Set([kSecReturnData, kSecReturnAttributes, kSecReturnRef, kSecReturnPersistentRef].map { $0 as String }.filter { dictionary[$0] == .bool(true) })
        }

        _ = try keychain.first(matching: query)
        #expect(returnKeys(lastCall?.dictionary ?? [:]) == [kSecReturnAttributes as String, kSecReturnData as String])
        #expect(lastCall?.dictionary[kSecMatchLimit as String] == nil)

        _ = try keychain.attributes(matching: query)
        #expect(returnKeys(lastCall?.dictionary ?? [:]) == [kSecReturnAttributes as String])

        _ = try keychain.data(matching: query)
        #expect(returnKeys(lastCall?.dictionary ?? [:]) == [kSecReturnData as String])

        _ = try keychain.persistentReference(matching: query)
        #expect(returnKeys(lastCall?.dictionary ?? [:]) == [kSecReturnPersistentRef as String])

        _ = try keychain.all(matching: query)
        #expect(returnKeys(lastCall?.dictionary ?? [:]) == [kSecReturnAttributes as String, kSecReturnPersistentRef as String])
        #expect(lastCall?.dictionary[kSecMatchLimit as String] == .string(kSecMatchLimitAll as String))

        _ = try keychain.allAttributes(matching: query)
        #expect(returnKeys(lastCall?.dictionary ?? [:]) == [kSecReturnAttributes as String])
        #expect(lastCall?.dictionary[kSecMatchLimit as String] == .string(kSecMatchLimitAll as String))
    }

    @Test func allFetchesDataPerItemThroughItsPersistentReferenceAndGroup() throws {
        backend.respond(with: .array([
            .dictionary([
                kSecClass as String: .string("genp"),
                kSecAttrAccount as String: .string("one"),
                kSecAttrAccessGroup as String: .string("TEAM.shared"),
                kSecValuePersistentRef as String: .data(Data([7])),
            ]),
        ]))
        let keychain = keychain(accessGroup: AccessGroup(rawValue: "TEAM.default"))
        _ = try? keychain.all(matching: query)

        let dataCall = try #require(lastCall)
        #expect(backend.calls.count == 2)
        #expect(dataCall.dictionary[kSecValuePersistentRef as String] == .data(Data([7])))
        #expect(dataCall.dictionary[kSecAttrAccessGroup as String] == .string("TEAM.shared"))
        #expect(dataCall.dictionary[kSecAttrSynchronizable as String] == .string(kSecAttrSynchronizableAny as String))
        #expect(dataCall.dictionary[kSecReturnData as String] == .bool(true))
    }

    @Test func updateSendsOnlyTheChanges() throws {
        var changes = Item<GenericPassword>(data: Data("new".utf8))
        changes[.label] = "label"
        try keychain().update(matching: query, with: changes)
        #expect(lastCall?.operation == .update)
        #expect(lastCall?.dictionary[kSecAttrService as String] == .string("service"))
        #expect(lastCall?.changes == [
            kSecAttrLabel as String: .string("label"),
            kSecValueData as String: .data(Data("new".utf8)),
        ])
    }

    @Test func unexpectedResultShapesAreReportedAsDecodingFailures() {
        backend.respond(with: .string("not a dictionary"))
        #expect(throws: KeychainError(code: .decodingFailed)) {
            try keychain().first(matching: query)
        }
        #expect(throws: KeychainError(code: .decodingFailed)) {
            try keychain().data(matching: query)
        }
    }

    #if os(macOS)
    @Test func fileBasedStorageUsesTheKeychainHandleAndItemList() throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        backend.respond(with: .data(Data([1])))
        let keychain = keychain(storage: .fileBased(temporary.fileKeychain))

        try keychain.add(Item<GenericPassword>(data: Data()))
        let addDictionary = try #require(lastCall?.dictionary)
        #expect(addDictionary[kSecUseDataProtectionKeychain as String] == nil)
        guard case .object(let used)? = addDictionary[kSecUseKeychain as String] else {
            Issue.record("expected kSecUseKeychain")
            return
        }
        // Kept outside the macro: `===` on `AnyObject` inside `#expect` crashes the Swift 6.4 compiler.
        let usesTemporaryKeychain = used.reference === temporary.fileKeychain.reference
        #expect(usesTemporaryKeychain)

        var byReference = query
        byReference.persistentReference = PersistentReference(rawValue: Data([9]))
        backend.respond(with: nil)
        _ = try keychain.first(matching: byReference)
        let searchDictionary = try #require(lastCall?.dictionary)
        #expect(searchDictionary[kSecMatchSearchList as String] == .array([.object(SecObject(temporary.fileKeychain.reference))]))
        #expect(searchDictionary[kSecValuePersistentRef as String] == nil)
        #expect(searchDictionary[kSecMatchItemList as String] == .array([.data(Data([9]))]))
    }

    @Test func defaultFileBasedStorageAddsNoStorageKeys() throws {
        _ = try keychain(storage: .fileBased()).first(matching: query)
        let dictionary = try #require(lastCall?.dictionary)
        #expect(dictionary[kSecUseDataProtectionKeychain as String] == nil)
        #expect(dictionary[kSecMatchSearchList as String] == nil)
    }
    #endif
}
