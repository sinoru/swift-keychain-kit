//
//  SmokeTests.swift
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

@Suite struct SmokeTests {
    @Test func errorPreservesStatusAndDescribesIt() {
        let error = KeychainError(status: errSecItemNotFound)
        #expect(error.status == errSecItemNotFound)
        #expect(error.description.contains("-25300"))
        #expect(error.description.contains("could not be found"))
    }

    @Test func itemClassesMapToSecClassConstants() {
        #expect(GenericPassword.secClass as String == kSecClassGenericPassword as String)
        #expect(InternetPassword.secClass as String == kSecClassInternetPassword as String)
        #expect(Certificate.secClass as String == kSecClassCertificate as String)
        #expect(CryptographicKey.secClass as String == kSecClassKey as String)
        #expect(Identity.secClass as String == kSecClassIdentity as String)
    }

    @Test func inMemoryBackendStartsEmpty() {
        let backend = InMemoryKeychainBackend()
        #expect(backend.itemCount == 0)
    }
}
