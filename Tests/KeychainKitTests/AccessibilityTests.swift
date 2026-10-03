//
//  AccessibilityTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Security
import Testing

@testable import KeychainKit

@Suite struct AccessibilityTests {
    @Test(arguments: [
        (Accessibility.whenUnlocked, kSecAttrAccessibleWhenUnlocked as String, false),
        (.afterFirstUnlock, kSecAttrAccessibleAfterFirstUnlock as String, false),
        (.whenPasscodeSetThisDeviceOnly, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String, true),
        (.whenUnlockedThisDeviceOnly, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String, true),
        (.afterFirstUnlockThisDeviceOnly, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String, true),
    ])
    func matchesSecurityConstants(accessibility: Accessibility, constant: String, isThisDeviceOnly: Bool) {
        #expect(accessibility.rawValue == constant)
        #expect(accessibility.isThisDeviceOnly == isThisDeviceOnly)
    }

    @Test func unknownValuesAreNotThisDeviceOnly() {
        #expect(!Accessibility(rawValue: "bogus").isThisDeviceOnly)
    }
}
