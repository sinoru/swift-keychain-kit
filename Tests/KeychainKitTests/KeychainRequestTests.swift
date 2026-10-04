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
        #expect(dictionaries.allSatisfy { $0[SecItemKey(kSecUseDataProtectionKeychain)] == .bool(true) })
    }

    @Test func defaultAccessGroupIsInjectedUnlessNamed() {
        let keychain = Keychain(accessGroup: AccessGroup(rawValue: "TEAM.default"))
        #expect(keychain.dictionary(for: query)[SecItemKey(kSecAttrAccessGroup)] == .string("TEAM.default"))

        var explicit = query
        explicit.accessGroup = AccessGroup(rawValue: "TEAM.other")
        #expect(keychain.dictionary(for: explicit)[SecItemKey(kSecAttrAccessGroup)] == .string("TEAM.other"))

        #expect(Keychain().dictionary(for: query)[SecItemKey(kSecAttrAccessGroup)] == nil)
    }

    @Test func addSendsClassDataAndAsksForAPersistentReference() {
        var item = Item<InternetPassword>(data: Data("secret".utf8))
        item.server = "example.com"
        let dictionary = Keychain().addDictionary(for: item)
        #expect(dictionary[SecItemKey(kSecClass)] == .string(kSecClassInternetPassword as String))
        #expect(dictionary[SecItemKey(kSecAttrServer)] == .string("example.com"))
        #expect(dictionary[SecItemKey(kSecValueData)] == .data(Data("secret".utf8)))
        #expect(dictionary[SecItemKey(kSecReturnPersistentRef)] == .bool(true))
        #expect(dictionary[SecItemKey(kSecReturnData)] == nil)
    }

    @Test func addOmitsDataWhenTheItemHasNone() {
        #expect(Keychain().addDictionary(for: Item<GenericPassword>())[SecItemKey(kSecValueData)] == nil)
    }

    @Test func searchesRequestOnlyTheKeysAsked() {
        let keychain = Keychain()
        func returnKeys(_ dictionary: SecDictionary) -> Set<SecItemKey> {
            Set([kSecReturnData, kSecReturnAttributes, kSecReturnRef, kSecReturnPersistentRef].map { SecItemKey($0) }.filter { dictionary[$0] == .bool(true) })
        }

        let first = keychain.requestDictionary(for: query, returning: [.attributes, .data], all: false)
        #expect(returnKeys(first) == [SecItemKey(kSecReturnAttributes), SecItemKey(kSecReturnData)])
        #expect(first[SecItemKey(kSecMatchLimit)] == nil)
        #expect(first[SecItemKey(kSecAttrService)] == .string("service"))

        #expect(returnKeys(keychain.requestDictionary(for: query, returning: .attributes, all: false)) == [SecItemKey(kSecReturnAttributes)])
        #expect(returnKeys(keychain.requestDictionary(for: query, returning: .data, all: false)) == [SecItemKey(kSecReturnData)])
        #expect(returnKeys(keychain.requestDictionary(for: query, returning: .persistentReference, all: false)) == [SecItemKey(kSecReturnPersistentRef)])

        let all = keychain.requestDictionary(for: query, returning: [.attributes, .persistentReference], all: true)
        #expect(returnKeys(all) == [SecItemKey(kSecReturnAttributes), SecItemKey(kSecReturnPersistentRef)])
        #expect(all[SecItemKey(kSecMatchLimit)] == .string(kSecMatchLimitAll as String))
    }

    /// The data protection keychain rejects an access group next to a persistent reference, so
    /// neither the keychain's default group nor one named on the query is sent with one.
    @Test func persistentReferenceIsSentWithoutAnAccessGroup() {
        let keychain = Keychain(accessGroup: AccessGroup(rawValue: "TEAM.default"))
        let reference = PersistentReference(rawValue: Data([7]))

        let dataRequest = keychain.requestDictionary(for: keychain.dataQuery(for: reference, inheriting: query), returning: .data, all: false)
        #expect(dataRequest[SecItemKey(kSecValuePersistentRef)] == .data(Data([7])))
        #expect(dataRequest[SecItemKey(kSecAttrAccessGroup)] == nil)
        #expect(dataRequest[SecItemKey(kSecAttrSynchronizable)] == .string(kSecAttrSynchronizableAny as String))
        #expect(dataRequest[SecItemKey(kSecReturnData)] == .bool(true))

        var named = Query<GenericPassword>()
        named.persistentReference = reference
        named.accessGroup = AccessGroup(rawValue: "TEAM.shared")
        #expect(keychain.requestDictionary(for: named, returning: .data, all: false)[SecItemKey(kSecAttrAccessGroup)] == nil)
        #expect(keychain.dictionary(for: named)[SecItemKey(kSecAttrAccessGroup)] == nil)

        var unreferenced = Query<GenericPassword>()
        unreferenced.accessGroup = AccessGroup(rawValue: "TEAM.shared")
        #expect(keychain.dictionary(for: unreferenced)[SecItemKey(kSecAttrAccessGroup)] == .string("TEAM.shared"))
    }

    @Test func skipFlagReachesSearchesButNotMutations() {
        var skipping = query
        skipping.skipsItemsRequiringAuthentication = true
        let keychain = Keychain()
        #expect(keychain.requestDictionary(for: skipping, returning: .data, all: false)[SecItemKey(kSecUseAuthenticationUI)] == .string(kSecUseAuthenticationUISkip as String))
        #expect(keychain.requestDictionary(for: query, returning: .data, all: false)[SecItemKey(kSecUseAuthenticationUI)] == nil)
        #expect(keychain.dictionary(for: skipping)[SecItemKey(kSecUseAuthenticationUI)] == nil)
    }

    /// The data protection keychain rejects a match limit in an update or delete, while the
    /// file-based keychain needs one to act on more than the first match.
    @Test func updateAndDeleteAskForEveryMatchOnlyOnTheFileBasedKeychain() {
        let dictionary = Keychain().dictionary(for: query)
        #expect(dictionary[SecItemKey(kSecMatchLimit)] == nil)
        #expect(dictionary[SecItemKey(kSecAttrService)] == .string("service"))

        #if os(macOS)
        let fileBased = Keychain(storage: .fileBased()).dictionary(for: query)
        #expect(fileBased[SecItemKey(kSecMatchLimit)] == .string(kSecMatchLimitAll as String))
        #endif
    }

    @Test func dataQueryInheritsTheSkipFlag() {
        let keychain = Keychain()
        var skipping = query
        skipping.skipsItemsRequiringAuthentication = true
        let reference = PersistentReference(rawValue: Data([7]))
        #expect(keychain.dataQuery(for: reference, inheriting: skipping).skipsItemsRequiringAuthentication)
        #expect(!keychain.dataQuery(for: reference, inheriting: query).skipsItemsRequiringAuthentication)
    }

    @Test func updateSendsOnlyTheChanges() {
        var changes = Item<GenericPassword>(data: Data("new".utf8))
        changes.label = "label"
        #expect(Keychain.updateDictionary(for: changes) == [
            SecItemKey(kSecAttrLabel): .string("label"),
            SecItemKey(kSecValueData): .data(Data("new".utf8)),
        ])
        #expect(Keychain.updateDictionary(for: Item<GenericPassword>()).isEmpty)
    }

    #if os(macOS)
    @Test func fileBasedStorageUsesTheKeychainHandleAndItemList() throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        let add = keychain.addDictionary(for: Item<GenericPassword>(data: Data()))
        #expect(add[SecItemKey(kSecUseDataProtectionKeychain)] == nil)
        guard case .object(let used)? = add[SecItemKey(kSecUseKeychain)] else {
            Issue.record("expected kSecUseKeychain")
            return
        }
        // Kept outside the macro: `===` on `AnyObject` inside `#expect` crashes the Swift 6.4 compiler.
        let usesTemporaryKeychain = used.reference === temporary.fileKeychain.reference
        #expect(usesTemporaryKeychain)

        var byReference = query
        byReference.persistentReference = PersistentReference(rawValue: Data([9]))
        let search = keychain.dictionary(for: byReference)
        #expect(search[SecItemKey(kSecMatchSearchList)] == .array([.object(SecObject(temporary.fileKeychain.reference))]))
        #expect(search[SecItemKey(kSecValuePersistentRef)] == nil)
        #expect(search[SecItemKey(kSecMatchItemList)] == .array([.data(Data([9]))]))
    }

    @Test func defaultFileBasedStorageAddsNoStorageKeys() {
        let dictionary = Keychain(storage: .fileBased()).dictionary(for: query)
        #expect(dictionary[SecItemKey(kSecUseDataProtectionKeychain)] == nil)
        #expect(dictionary[SecItemKey(kSecMatchSearchList)] == nil)
    }
    #endif
}
