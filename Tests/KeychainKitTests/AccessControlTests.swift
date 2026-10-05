//
//  AccessControlTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

@Suite struct AccessControlTests {
    @Test(arguments: [
        (AccessControl.Flags.userPresence, SecAccessControlCreateFlags.userPresence),
        (.biometryAny, .biometryAny),
        (.biometryCurrentSet, .biometryCurrentSet),
        (.devicePasscode, .devicePasscode),
        (.or, .or),
        (.and, .and),
        (.privateKeyUsage, .privateKeyUsage),
        (.applicationPassword, .applicationPassword),
    ])
    func flagsMirrorSecurityConstants(flag: AccessControl.Flags, constant: SecAccessControlCreateFlags) {
        #expect(flag.rawValue == UInt(constant.rawValue))
    }

    @Test func companionFlagMirrorsSecurityConstantWhereAvailable() {
        #if os(macOS) || os(iOS)
        if #available(macOS 15.0, iOS 18.0, *) {
            #expect(AccessControl.Flags.companion.rawValue == UInt(SecAccessControlCreateFlags.companion.rawValue))
        }
        #endif
    }

    @Test func combinedFlags() throws {
        let control = try AccessControl(accessibility: .whenPasscodeSetThisDeviceOnly, flags: [.biometryAny, .or, .devicePasscode])
        #expect(control.accessibility == .whenPasscodeSetThisDeviceOnly)
        #expect(control.flags == [.biometryAny, .or, .devicePasscode])
        #expect(CFGetTypeID(control.secObject.reference) == SecAccessControlGetTypeID())
    }

    @Test func rejectsUnknownAccessibility() {
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try AccessControl(accessibility: Accessibility(rawValue: "bogus"), flags: .userPresence)
        }
    }

    @Test(arguments: [
        [AccessControl.Flags.or, .and],
        [.biometryAny, .biometryCurrentSet],
        [.userPresence, .devicePasscode],
    ] as [AccessControl.Flags])
    func conflictingFlagCombinations(flags: AccessControl.Flags) {
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try AccessControl(accessibility: .whenUnlocked, flags: flags)
        }
    }

    @Test func comparesByConstraintsNotObjectIdentity() throws {
        let first = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
        let second = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
        let different = try AccessControl(accessibility: .whenUnlocked, flags: .devicePasscode)
        #expect(first == second)
        #expect(first.hashValue == second.hashValue)
        #expect(first != different)
        #expect(first.secObject != second.secObject)
    }

    @Test func opaqueValuesCompareByContentsNotObjectIdentity() throws {
        let userPresence = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence).secObject
        let first = AccessControl(opaque: userPresence, accessibility: .whenUnlocked)
        let second = AccessControl(
            opaque: try AccessControl(accessibility: .whenUnlocked, flags: .userPresence).secObject,
            accessibility: .whenUnlocked,
        )
        let different = AccessControl(
            opaque: try AccessControl(accessibility: .whenUnlocked, flags: .devicePasscode).secObject,
            accessibility: .whenUnlocked,
        )
        #expect(first.secObject != second.secObject)
        #expect(first == second)
        #expect(first.hashValue == second.hashValue)
        #expect(first != different)
        #expect(first != AccessControl(opaque: userPresence, accessibility: nil))
    }

    @Test func mapsStatusDomainErrorsToTheirStatus() {
        let error = CFErrorCreate(nil, NSOSStatusErrorDomain as CFString, CFIndex(errSecDuplicateItem), nil)
        #expect(KeychainError(cfError: error).code == .duplicateItem)
    }

    @Test func mapsUnknownDomainErrorsToInternalError() {
        let error = CFErrorCreate(nil, "com.example" as CFString, 42, nil)
        #expect(KeychainError(cfError: error).code == .internalError)
    }

    @Test func mapsMissingErrorToInvalidParameter() {
        #expect(KeychainError(cfError: nil).code == .invalidParameter)
    }
}
