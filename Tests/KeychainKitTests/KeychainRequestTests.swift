//
//  KeychainRequestTests.swift
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

/// Checks the dictionaries a `Keychain` builds for the framework, without calling it.
@Suite struct KeychainRequestTests {
    private var query: Query<GenericPassword> {
        Query(service: "service")
    }

    @Test func dataProtectionStorageIsRequestedOnEveryCall() {
        let keychain = Keychain()
        let dictionaries = [
            keychain.addDictionary(for: Item<GenericPassword>(data: Data())),
            keychain.requestDictionary(for: query, returning: .data, all: false),
            keychain.dictionary(for: query),
        ]
        #expect(dictionaries.allSatisfy { $0[kSecUseDataProtectionKeychain as String] == .bool(true) })
    }

    @Test func defaultAccessGroupIsInjectedUnlessNamed() {
        let keychain = Keychain(accessGroup: AccessGroup(rawValue: "TEAM.default"))
        #expect(keychain.dictionary(for: query)[kSecAttrAccessGroup as String] == .string("TEAM.default"))

        var explicit = query
        explicit[.accessGroup] = AccessGroup(rawValue: "TEAM.other")
        #expect(keychain.dictionary(for: explicit)[kSecAttrAccessGroup as String] == .string("TEAM.other"))

        #expect(Keychain().dictionary(for: query)[kSecAttrAccessGroup as String] == nil)
    }

    @Test func addSendsClassDataAndAsksForAPersistentReference() {
        var item = Item<InternetPassword>(data: Data("secret".utf8))
        item[.server] = "example.com"
        let dictionary = Keychain().addDictionary(for: item)
        #expect(dictionary[kSecClass as String] == .string(kSecClassInternetPassword as String))
        #expect(dictionary[kSecAttrServer as String] == .string("example.com"))
        #expect(dictionary[kSecValueData as String] == .data(Data("secret".utf8)))
        #expect(dictionary[kSecReturnPersistentRef as String] == .bool(true))
        #expect(dictionary[kSecReturnData as String] == nil)
    }

    @Test func addOmitsDataWhenTheItemHasNone() {
        #expect(Keychain().addDictionary(for: Item<GenericPassword>())[kSecValueData as String] == nil)
    }

    @Test func searchesRequestOnlyTheKeysAsked() {
        let keychain = Keychain()
        func returnKeys(_ dictionary: SecDictionary) -> Set<String> {
            Set([kSecReturnData, kSecReturnAttributes, kSecReturnRef, kSecReturnPersistentRef].map { $0 as String }.filter { dictionary[$0] == .bool(true) })
        }

        let first = keychain.requestDictionary(for: query, returning: [.attributes, .data], all: false)
        #expect(returnKeys(first) == [kSecReturnAttributes as String, kSecReturnData as String])
        #expect(first[kSecMatchLimit as String] == nil)
        #expect(first[kSecAttrService as String] == .string("service"))

        #expect(returnKeys(keychain.requestDictionary(for: query, returning: .attributes, all: false)) == [kSecReturnAttributes as String])
        #expect(returnKeys(keychain.requestDictionary(for: query, returning: .data, all: false)) == [kSecReturnData as String])
        #expect(returnKeys(keychain.requestDictionary(for: query, returning: .persistentReference, all: false)) == [kSecReturnPersistentRef as String])

        let all = keychain.requestDictionary(for: query, returning: [.attributes, .persistentReference], all: true)
        #expect(returnKeys(all) == [kSecReturnAttributes as String, kSecReturnPersistentRef as String])
        #expect(all[kSecMatchLimit as String] == .string(kSecMatchLimitAll as String))
    }

    @Test func dataQueryCarriesReferenceGroupAndAnySynchronizable() {
        let keychain = Keychain(accessGroup: AccessGroup(rawValue: "TEAM.default"))
        var attributes = Attributes<GenericPassword>()
        attributes[.accessGroup] = AccessGroup(rawValue: "TEAM.shared")
        let dictionary = keychain.requestDictionary(
            for: keychain.dataQuery(for: attributes, reference: PersistentReference(rawValue: Data([7])), inheriting: query),
            returning: .data,
            all: false,
        )
        #expect(dictionary[kSecValuePersistentRef as String] == .data(Data([7])))
        #expect(dictionary[kSecAttrAccessGroup as String] == .string("TEAM.shared"))
        #expect(dictionary[kSecAttrSynchronizable as String] == .string(kSecAttrSynchronizableAny as String))
        #expect(dictionary[kSecReturnData as String] == .bool(true))

        let ungrouped = keychain.requestDictionary(
            for: keychain.dataQuery(for: Attributes<GenericPassword>(), reference: PersistentReference(rawValue: Data([7])), inheriting: query),
            returning: .data,
            all: false,
        )
        #expect(ungrouped[kSecAttrAccessGroup as String] == .string("TEAM.default"))
    }

    @Test func updateAndDeleteAskForEveryMatch() {
        let dictionary = Keychain().dictionary(for: query)
        #expect(dictionary[kSecMatchLimit as String] == .string(kSecMatchLimitAll as String))
        #expect(dictionary[kSecAttrService as String] == .string("service"))
    }

    @Test func updateSendsOnlyTheChanges() {
        var changes = Item<GenericPassword>(data: Data("new".utf8))
        changes[.label] = "label"
        #expect(Keychain.updateDictionary(for: changes) == [
            kSecAttrLabel as String: .string("label"),
            kSecValueData as String: .data(Data("new".utf8)),
        ])
        #expect(Keychain.updateDictionary(for: Item<GenericPassword>()).isEmpty)
    }

    #if os(macOS)
    @Test func fileBasedStorageUsesTheKeychainHandleAndItemList() throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        let add = keychain.addDictionary(for: Item<GenericPassword>(data: Data()))
        #expect(add[kSecUseDataProtectionKeychain as String] == nil)
        guard case .object(let used)? = add[kSecUseKeychain as String] else {
            Issue.record("expected kSecUseKeychain")
            return
        }
        // Kept outside the macro: `===` on `AnyObject` inside `#expect` crashes the Swift 6.4 compiler.
        let usesTemporaryKeychain = used.reference === temporary.fileKeychain.reference
        #expect(usesTemporaryKeychain)

        var byReference = query
        byReference.persistentReference = PersistentReference(rawValue: Data([9]))
        let search = keychain.dictionary(for: byReference)
        #expect(search[kSecMatchSearchList as String] == .array([.object(SecObject(temporary.fileKeychain.reference))]))
        #expect(search[kSecValuePersistentRef as String] == nil)
        #expect(search[kSecMatchItemList as String] == .array([.data(Data([9]))]))
    }

    @Test func defaultFileBasedStorageAddsNoStorageKeys() {
        let dictionary = Keychain(storage: .fileBased()).dictionary(for: query)
        #expect(dictionary[kSecUseDataProtectionKeychain as String] == nil)
        #expect(dictionary[kSecMatchSearchList as String] == nil)
    }
    #endif
}
