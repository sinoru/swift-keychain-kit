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
        .dictionary([
            SecItemKey(rawValue: "svce"): .string("service"),
            SecItemKey(rawValue: "v_Data"): .data(Data("secret".utf8)),
            SecItemKey(rawValue: "sync"): .bool(false),
        ]),
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
        let dictionary: SecDictionary = [SecItemKey(kSecAttrService): .string("service")]
        let roundTripped = SecDictionary(cf: dictionary.cfDictionary as NSDictionary)
        #expect(roundTripped == dictionary)
        #expect(roundTripped?[SecItemKey(rawValue: "svce")] == .string("service"))
    }

    @Test func dictionaryWithNonStringKeyIsCarriedAsObject() {
        let dictionary: NSDictionary = [1: "one"]
        #expect(SecDictionary(cf: dictionary) == nil)
        #expect(SecValue(cf: dictionary) == .object(SecObject(dictionary)))
    }

    @Test func booleansAndNumbersAreNotConfused() {
        #expect(SecValue(cf: kCFBooleanTrue) == .bool(true))
        #expect(SecValue(cf: 1 as CFNumber) == .integer(1))
        #expect(SecValue(cf: UInt32.max as CFNumber) == .integer(Int64(UInt32.max)))
    }

    @Test func numbersAreIntegersOnlyWhenStoredAsIntegers() {
        #expect(SecValue(cf: NSNumber(value: Int64.min)) == .integer(.min))
        #expect(SecValue(cf: NSNumber(value: Int64.max)) == .integer(.max))
        #expect(SecValue(cf: NSNumber(value: -1)) == .integer(-1))

        // The keychain hands back a number of the type it stored, so a floating-point one is
        // not an integer attribute even when its value is whole.
        let whole = NSNumber(value: 2.0)
        #expect(SecValue(cf: whole) == .object(SecObject(whole)))
        let fraction = NSNumber(value: 1.5)
        #expect(SecValue(cf: fraction) == .object(SecObject(fraction)))
        let beyondInt64 = NSNumber(value: UInt64.max)
        #expect(SecValue(cf: beyondInt64) == .object(SecObject(beyondInt64)))
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
