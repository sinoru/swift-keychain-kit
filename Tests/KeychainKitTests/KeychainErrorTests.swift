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
}
