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
        let error = KeychainError(code: .itemNotFound)
        #expect(error.description.contains("-25300"))
        #expect(error.description.contains("could not be found"))
        #expect(error.errorDescription == error.description)
        #expect(error.localizedDescription == error.description)
    }

    @Test func describesUnknownStatusByNumberAlone() {
        let error = KeychainError(status: -99_999)
        #expect(error.description.contains("-99999"))
    }
}
