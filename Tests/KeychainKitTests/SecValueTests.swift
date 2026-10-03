//
//  SecValueTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

@Suite struct SecValueTests {
    @Test(arguments: [
        SecValue.string("account"),
        .data(Data([0x00, 0xFF, 0x10])),
        .bool(true),
        .bool(false),
        .integer(443),
        .integer(-1),
        .integer(0xFFFF_FFFF),
        .integer(Int64.max),
        .integer(Int64.min),
        .date(Date(timeIntervalSince1970: 1_700_000_000)),
        .array([.string("a"), .integer(1)]),
        .dictionary(["svce": .string("service"), "v_Data": .data(Data("secret".utf8)), "sync": .bool(false)]),
    ])
    func roundTripsThroughCoreFoundation(_ value: SecValue) {
        #expect(SecValue(cf: value.cfValue) == value)
    }

    @Test func constantsRoundTripAsTheirRawStrings() {
        let value = SecValue(cf: kSecClassGenericPassword)
        #expect(value == .string("genp"))
        #expect(value.cfValue as? String == kSecClassGenericPassword as String)
    }

    @Test func dictionaryKeysAreRawConstantStrings() {
        let dictionary: SecDictionary = [kSecAttrService as String: .string("service")]
        let roundTripped = SecDictionary(cf: dictionary.cfDictionary as NSDictionary as! [String: Any])
        #expect(roundTripped == dictionary)
        #expect(roundTripped["svce"] == .string("service"))
    }

    @Test func booleansAndNumbersAreNotConfused() {
        #expect(SecValue(cf: kCFBooleanTrue) == .bool(true))
        #expect(SecValue(cf: 1 as CFNumber) == .integer(1))
        #expect(SecValue(cf: UInt32.max as CFNumber) == .integer(Int64(UInt32.max)))
    }

    @Test func unknownObjectsAreCarriedThrough() {
        let object = NSObject()
        let value = SecValue(cf: object)
        #expect(value == .object(SecObject(object)))
        // Kept outside the macro: `===` on `AnyObject` inside `#expect` crashes the Swift 6.4 compiler.
        let isSameObject = value.cfValue === object
        #expect(isSameObject)
    }

    @Test func objectsCompareByIdentity() {
        let first = SecObject(NSObject())
        let second = SecObject(NSObject())
        #expect(first == first)
        #expect(first != second)
    }
}
