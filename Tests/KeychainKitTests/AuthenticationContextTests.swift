//
//  AuthenticationContextTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if canImport(LocalAuthentication) && !os(tvOS)
import Foundation
import LocalAuthentication
import Security
import Testing

@testable import KeychainKit

@Suite struct AuthenticationContextTests {
    private func isSameContext(_ value: SecValue?, as context: LAContext) -> Bool {
        guard case .object(let object)? = value else {
            return false
        }
        return object.reference === context
    }

    @Test func queriesCarryTheContext() {
        let context = LAContext()
        var query = Query<GenericPassword>()
        query.authenticationContext = AuthenticationContext(context)
        let keychain = Keychain()
        #expect(isSameContext(keychain.dictionary(for: query)[kSecUseAuthenticationContext as String], as: context))
        #expect(isSameContext(keychain.requestDictionary(for: query, returning: .data, all: false)[kSecUseAuthenticationContext as String], as: context))
        #expect(keychain.dictionary(for: Query<GenericPassword>())[kSecUseAuthenticationContext as String] == nil)
    }

    @Test func addCarriesTheContext() {
        let context = LAContext()
        let keychain = Keychain()
        let item = Item<GenericPassword>(data: Data())
        #expect(isSameContext(keychain.addDictionary(for: item, authenticationContext: AuthenticationContext(context))[kSecUseAuthenticationContext as String], as: context))
        #expect(keychain.addDictionary(for: item, authenticationContext: nil)[kSecUseAuthenticationContext as String] == nil)
    }

    @Test func dataQueriesInheritTheContextButNotTheSkipFlag() {
        let context = LAContext()
        var original = Query<GenericPassword>()
        original.authenticationContext = AuthenticationContext(context)
        original.skipsItemsRequiringAuthentication = true
        let keychain = Keychain()
        let dataQuery = keychain.dataQuery(for: Attributes(), reference: PersistentReference(rawValue: Data([1])), inheriting: original)
        #expect(dataQuery.authenticationContext == AuthenticationContext(context))
        #expect(!dataQuery.skipsItemsRequiringAuthentication)
        #expect(isSameContext(keychain.requestDictionary(for: dataQuery, returning: .data, all: false)[kSecUseAuthenticationContext as String], as: context))
    }

    @Test func comparesByIdentity() {
        let context = LAContext()
        #expect(AuthenticationContext(context) == AuthenticationContext(context))
        #expect(AuthenticationContext(context) != AuthenticationContext(LAContext()))
        #expect(AuthenticationContext(context).hashValue == AuthenticationContext(context).hashValue)
    }
}
#endif
