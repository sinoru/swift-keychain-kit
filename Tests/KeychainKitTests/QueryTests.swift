//
//  QueryTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

@Suite struct QueryTests {
    @Test func includesClassAndAttributes() {
        var query = Query<GenericPassword>()
        query.service = "service"
        query.account = "account"
        #expect(query.secDictionary == [
            SecItemKey(kSecClass): .string(kSecClassGenericPassword as String),
            SecItemKey(kSecAttrService): .string("service"),
            SecItemKey(kSecAttrAccount): .string("account"),
        ])
    }

    @Test func usesTheClassOfItsTypeParameter() {
        #expect(Query<InternetPassword>().secDictionary[SecItemKey(kSecClass)] == .string(kSecClassInternetPassword as String))
    }

    @Test func synchronizableMatchOverridesTheAttribute() {
        // `query.synchronizable` is the match mode; the attribute of the same name is only
        // reachable through `attributes`, and the match mode wins when the dictionary is built.
        var query = Query<GenericPassword>()
        query.attributes.synchronizable = true

        query.synchronizable = .nonSynchronizableOnly
        #expect(query.secDictionary[SecItemKey(kSecAttrSynchronizable)] == nil)

        query.synchronizable = .synchronizableOnly
        #expect(query.secDictionary[SecItemKey(kSecAttrSynchronizable)] == .bool(true))

        query.synchronizable = .any
        #expect(query.secDictionary[SecItemKey(kSecAttrSynchronizable)] == .string(kSecAttrSynchronizableAny as String))
    }

    @Test func skipFlagStaysOutOfTheQueryDictionary() {
        // The flag is search-only, so `Keychain.requestDictionary` adds it; see KeychainRequestTests.
        var query = Query<GenericPassword>()
        query.skipsItemsRequiringAuthentication = true
        #expect(query.secDictionary[SecItemKey(kSecUseAuthenticationUI)] == nil)
    }

    @Test func carriesAPersistentReference() {
        var query = Query<GenericPassword>()
        query.persistentReference = PersistentReference(rawValue: Data([9, 9]))
        #expect(query.secDictionary[SecItemKey(kSecValuePersistentRef)] == .data(Data([9, 9])))
    }

    @Test func carriesProtection() throws {
        var query = Query<GenericPassword>()
        query.attributes.protection = .accessible(.afterFirstUnlock)
        #expect(query.secDictionary[SecItemKey(kSecAttrAccessible)] == .string(kSecAttrAccessibleAfterFirstUnlock as String))
    }

    @Test func persistentReferenceRoundTripsThroughCodable() throws {
        let reference = PersistentReference(rawValue: Data([1, 2, 3]))
        let encoded = try JSONEncoder().encode(reference)
        #expect(try JSONDecoder().decode(PersistentReference.self, from: encoded) == reference)
    }
}
