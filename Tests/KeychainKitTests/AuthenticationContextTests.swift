//
//  AuthenticationContextTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if canImport(LocalAuthentication)
import Foundation
import LocalAuthentication
import Security
import Testing

@testable import KeychainKit
import KeychainKitTestSupport

@Suite struct AuthenticationContextTests {
    private let backend = RecordingKeychainBackend()

    private var keychain: Keychain {
        Keychain(backend: backend, storage: .dataProtection, accessGroup: nil)
    }

    private func isSameContext(_ value: SecValue?, as context: LAContext) -> Bool {
        guard case .object(let object)? = value else {
            return false
        }
        return object.reference === context
    }

    @Test func queriesCarryTheContext() throws {
        let context = LAContext()
        var query = Query<GenericPassword>()
        query.authenticationContext = AuthenticationContext(context)
        _ = try keychain.first(matching: query)
        try keychain.update(matching: query, with: Item(data: Data()))
        try keychain.delete(matching: query)
        #expect(backend.calls.count == 3)
        #expect(backend.calls.allSatisfy { isSameContext($0.dictionary[kSecUseAuthenticationContext as String], as: context) })
    }

    @Test func addCarriesTheContext() throws {
        backend.respond(with: .data(Data([1])))
        let context = LAContext()
        try keychain.add(Item<GenericPassword>(data: Data()), authenticationContext: AuthenticationContext(context))
        #expect(isSameContext(backend.calls.last?.dictionary[kSecUseAuthenticationContext as String], as: context))

        try keychain.add(Item<GenericPassword>(data: Data()))
        #expect(backend.calls.last?.dictionary[kSecUseAuthenticationContext as String] == nil)
    }

    @Test func comparesByIdentity() {
        let context = LAContext()
        #expect(AuthenticationContext(context) == AuthenticationContext(context))
        #expect(AuthenticationContext(context) != AuthenticationContext(LAContext()))
        #expect(AuthenticationContext(context).hashValue == AuthenticationContext(context).hashValue)
    }
}
#endif
