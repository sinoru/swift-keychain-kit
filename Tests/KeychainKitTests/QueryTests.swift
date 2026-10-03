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
        query[.service] = "service"
        query[.account] = "account"
        #expect(query.secDictionary == [
            kSecClass as String: .string(kSecClassGenericPassword as String),
            kSecAttrService as String: .string("service"),
            kSecAttrAccount as String: .string("account"),
        ])
    }

    @Test func usesTheClassOfItsTypeParameter() {
        #expect(Query<InternetPassword>().secDictionary[kSecClass as String] == .string(kSecClassInternetPassword as String))
    }

    @Test func synchronizableMatchOverridesTheAttributeKey() {
        var query = Query<GenericPassword>()
        query[.synchronizable] = true

        query.synchronizable = .nonSynchronizableOnly
        #expect(query.secDictionary[kSecAttrSynchronizable as String] == nil)

        query.synchronizable = .synchronizableOnly
        #expect(query.secDictionary[kSecAttrSynchronizable as String] == .bool(true))

        query.synchronizable = .any
        #expect(query.secDictionary[kSecAttrSynchronizable as String] == .string(kSecAttrSynchronizableAny as String))
    }

    @Test func skipFlagStaysOutOfTheQueryDictionary() {
        // The flag is search-only, so `Keychain.requestDictionary` adds it; see KeychainRequestTests.
        var query = Query<GenericPassword>()
        query.skipsItemsRequiringAuthentication = true
        #expect(query.secDictionary[kSecUseAuthenticationUI as String] == nil)
    }

    @Test func carriesAPersistentReference() {
        var query = Query<GenericPassword>()
        query.persistentReference = PersistentReference(rawValue: Data([9, 9]))
        #expect(query.secDictionary[kSecValuePersistentRef as String] == .data(Data([9, 9])))
    }

    @Test func carriesProtection() throws {
        var query = Query<GenericPassword>()
        query.attributes.protection = .accessible(.afterFirstUnlock)
        #expect(query.secDictionary[kSecAttrAccessible as String] == .string(kSecAttrAccessibleAfterFirstUnlock as String))
    }

    @Test func persistentReferenceRoundTripsThroughCodable() throws {
        let reference = PersistentReference(rawValue: Data([1, 2, 3]))
        let encoded = try JSONEncoder().encode(reference)
        #expect(try JSONDecoder().decode(PersistentReference.self, from: encoded) == reference)
    }
}
