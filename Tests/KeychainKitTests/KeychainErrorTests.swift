//
//  KeychainErrorTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication
#endif

#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif

@testable import KeychainKit

@Suite struct KeychainErrorTests {
    @Test(arguments: [
        (errSecDuplicateItem, KeychainError.Code.duplicateItem),
        (errSecItemNotFound, .itemNotFound),
        (errSecMissingEntitlement, .missingEntitlement),
        (errSecInteractionNotAllowed, .interactionNotAllowed),
        (errSecAuthFailed, .authenticationFailed),
        (errSecUserCanceled, .userCanceled),
        (errSecParam, .invalidParameter),
        (errSecNotAvailable, .notAvailable),
        (errSecDecode, .decodingFailed),
        (errSecDataTooLarge, .dataTooLarge),
        (errSecReadOnly, .readOnly),
        (errSecInvalidItemRef, .invalidItemReference),
        (errSecUnimplemented, .unimplemented),
        (errSecAllocate, .allocationFailed),
        (errSecIO, .ioFailed),
        (errSecInternalError, .internalError),
    ])
    func classifiesWellKnownStatuses(status: OSStatus, code: KeychainError.Code) {
        let error = KeychainError(status: status)
        #expect(error.code == code)
        #expect(KeychainError(code: code) == error)
    }

    @Test func preservesStatusesItDoesNotName() {
        let error = KeychainError(status: -99_999)
        #expect(error.status == -99_999)
        #expect(error.code.rawValue == -99_999)
    }

    @Test func describesStatusWithMessageAndNumber() {
        // The message comes from the framework in the process's locale, so only its presence
        // is checked, not its wording: the description must be more than the numeric fallback.
        let error = KeychainError(code: .itemNotFound)
        #expect(error.description.hasSuffix("(-25300)"))
        #expect(error.description != "OSStatus -25300")
        #expect(error.description.count > "(-25300)".count)
        #expect(error.errorDescription == error.description)
        #expect(error.localizedDescription == error.description)
    }

    @Test func describesUnknownStatusByNumberAlone() {
        let error = KeychainError(status: -99_999)
        #expect(error.description.contains("-99999"))
    }

    // The expectations below follow the framework's classification for the SecItem functions.
    @Test(arguments: [
        (-2, KeychainError.Code.userCanceled),
        (-1001, .invalidParameter),
        (-1004, .interactionNotAllowed),
        (-1, .authenticationFailed),
        (-8, .authenticationFailed),
    ])
    func mapsLocalAuthenticationErrors(code: Int, expected: KeychainError.Code) {
        let error = CFErrorCreate(nil, "com.apple.LocalAuthentication" as CFString, code, nil)
        #expect(KeychainError(cfError: error).code == expected)
    }

    @Test(arguments: [
        (-8, KeychainError.Code.invalidParameter),
        (-1, .unimplemented),
        (-4, .userCanceled),
        (-3, .decodingFailed),
        (-6, .itemNotFound),
        (-7, .itemNotFound),
        (-2, .internalError),
        (-5, .internalError),
        (-9, .internalError),
    ])
    func mapsCryptoTokenKitErrors(code: Int, expected: KeychainError.Code) {
        let error = CFErrorCreate(nil, "CryptoTokenKit" as CFString, code, nil)
        #expect(KeychainError(cfError: error).code == expected)
    }

    // Only a `CFIndex` wider than an `OSStatus` can hold a code outside the status range.
    @Test(.enabled(if: CFIndex.bitWidth > OSStatus.bitWidth))
    func mapsStatusDomainCodeOutsideTheStatusRangeToInternalError() {
        let code = CFIndex(truncatingIfNeeded: Int64(Int32.max) + 1)
        let error = CFErrorCreate(nil, NSOSStatusErrorDomain as CFString, code, nil)
        #expect(KeychainError(cfError: error).code == .internalError)
    }

    // The library compares these domains and codes as literals. These tests hold the literals
    // to the constants the frameworks declare.
    #if canImport(LocalAuthentication) && !os(tvOS)
    @Test func localAuthenticationLiteralsMatchTheFramework() {
        #expect(LAErrorDomain == "com.apple.LocalAuthentication")
        #expect(LAError.Code.userCancel.rawValue == -2)
        #expect(LAError.Code.notInteractive.rawValue == -1004)
    }
    #endif

    #if canImport(CryptoTokenKit)
    @Test func cryptoTokenKitLiteralsMatchTheFramework() {
        #expect(TKErrorDomain == "CryptoTokenKit")
        #expect(TKError.Code.badParameter.rawValue == -8)
        #expect(TKError.Code.notImplemented.rawValue == -1)
        #expect(TKError.Code.canceledByUser.rawValue == -4)
        #expect(TKError.Code.corruptedData.rawValue == -3)
        #expect(TKError.Code.objectNotFound.rawValue == -6)
        #expect(TKError.Code.tokenNotFound.rawValue == -7)
    }
    #endif
}
