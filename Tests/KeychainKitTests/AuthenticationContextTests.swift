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
        #expect(isSameContext(keychain.dictionary(for: query)[SecItemKey(kSecUseAuthenticationContext)], as: context))
        #expect(isSameContext(keychain.requestDictionary(for: query, returning: .data, all: false)[SecItemKey(kSecUseAuthenticationContext)], as: context))
        #expect(keychain.dictionary(for: Query<GenericPassword>())[SecItemKey(kSecUseAuthenticationContext)] == nil)
    }

    @Test func addCarriesTheContext() {
        let context = LAContext()
        let keychain = Keychain()
        let item = Item<GenericPassword>(data: Data())
        #expect(isSameContext(keychain.addDictionary(for: item, authenticationContext: AuthenticationContext(context))[SecItemKey(kSecUseAuthenticationContext)], as: context))
        #expect(keychain.addDictionary(for: item, authenticationContext: nil)[SecItemKey(kSecUseAuthenticationContext)] == nil)
    }

    /// The context sits at the top level of the generation request, not among the stored key's
    /// attributes.
    @Test func keyGenerationCarriesTheContext() throws {
        let context = LAContext()
        let keychain = Keychain()
        let attributes = try Keychain.secureEnclaveKeyAttributes(
            applicationTag: nil, label: nil, accessGroup: nil, accessibility: .whenUnlockedThisDeviceOnly, constraints: .applicationPassword,
        )
        let dictionary = keychain.generationDictionary(
            for: .ecSECPrimeRandom, sizeInBits: 256, attributes: attributes, authenticationContext: AuthenticationContext(context),
        )
        #expect(isSameContext(dictionary[SecItemKey(kSecUseAuthenticationContext)], as: context))
        guard case .dictionary(let privateKey)? = dictionary[SecItemKey(kSecPrivateKeyAttrs)] else {
            Issue.record("no private key attributes")
            return
        }
        #expect(privateKey[SecItemKey(kSecUseAuthenticationContext)] == nil)

        let without = keychain.generationDictionary(for: .ecSECPrimeRandom, sizeInBits: 256, attributes: attributes, authenticationContext: nil)
        #expect(without[SecItemKey(kSecUseAuthenticationContext)] == nil)
    }

    #if os(macOS)
    @Test func dataQueriesInheritTheContextAndTheSkipFlag() {
        let context = LAContext()
        var original = Query<GenericPassword>()
        original.authenticationContext = AuthenticationContext(context)
        original.skipsItemsRequiringAuthentication = true
        let keychain = Keychain()
        let dataQuery = keychain.dataQuery(for: PersistentReference(rawValue: Data([1])), inheriting: original)
        #expect(dataQuery.authenticationContext == AuthenticationContext(context))
        #expect(dataQuery.skipsItemsRequiringAuthentication)
        #expect(isSameContext(keychain.requestDictionary(for: dataQuery, returning: .data, all: false)[SecItemKey(kSecUseAuthenticationContext)], as: context))
    }
    #endif

    @Test func comparesByIdentity() {
        let context = LAContext()
        #expect(AuthenticationContext(context) == AuthenticationContext(context))
        #expect(AuthenticationContext(context) != AuthenticationContext(LAContext()))
        #expect(AuthenticationContext(context).hashValue == AuthenticationContext(context).hashValue)
    }
}
#endif
