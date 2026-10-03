//
//  AttributeKeyTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

@Suite struct AttributeKeyTests {
    @Test func rawKeysMatchSecurityConstants() {
        #expect(AttributeKey<GenericPassword, String>.label.rawKey == kSecAttrLabel as String)
        #expect(AttributeKey<GenericPassword, AccessGroup>.accessGroup.rawKey == kSecAttrAccessGroup as String)
        #expect(AttributeKey<GenericPassword, Bool>.synchronizable.rawKey == kSecAttrSynchronizable as String)
        #expect(ReadOnlyAttributeKey<GenericPassword, Date>.creationDate.rawKey == kSecAttrCreationDate as String)
        #expect(ReadOnlyAttributeKey<GenericPassword, Date>.modificationDate.rawKey == kSecAttrModificationDate as String)

        #expect(AttributeKey<GenericPassword, String>.account.rawKey == kSecAttrAccount as String)
        #expect(AttributeKey<GenericPassword, String>.description.rawKey == kSecAttrDescription as String)
        #expect(AttributeKey<GenericPassword, String>.comment.rawKey == kSecAttrComment as String)
        #expect(AttributeKey<GenericPassword, UInt32>.creator.rawKey == kSecAttrCreator as String)
        #expect(AttributeKey<GenericPassword, UInt32>.type.rawKey == kSecAttrType as String)
        #expect(AttributeKey<GenericPassword, Bool>.isInvisible.rawKey == kSecAttrIsInvisible as String)
        #expect(AttributeKey<GenericPassword, Bool>.isNegative.rawKey == kSecAttrIsNegative as String)
        #expect(AttributeKey<GenericPassword, String>.service.rawKey == kSecAttrService as String)
        #expect(AttributeKey<GenericPassword, Data>.generic.rawKey == kSecAttrGeneric as String)

        #expect(AttributeKey<InternetPassword, String>.server.rawKey == kSecAttrServer as String)
        #expect(AttributeKey<InternetPassword, String>.securityDomain.rawKey == kSecAttrSecurityDomain as String)
        #expect(AttributeKey<InternetPassword, String>.path.rawKey == kSecAttrPath as String)
        #expect(AttributeKey<InternetPassword, InternetProtocol>.internetProtocol.rawKey == kSecAttrProtocol as String)
        #expect(AttributeKey<InternetPassword, AuthenticationType>.authenticationType.rawKey == kSecAttrAuthenticationType as String)
        #expect(AttributeKey<InternetPassword, Int>.port.rawKey == kSecAttrPort as String)
    }

    @Test func valuesRoundTripThroughAttributes() throws {
        var attributes = Attributes<InternetPassword>()
        let group = try #require(AccessGroup(rawValue: "TEAM.group"))
        attributes[.label] = "label"
        attributes[.accessGroup] = group
        attributes[.synchronizable] = true
        attributes[.account] = "account"
        attributes[.creator] = 0x4B_43_48_4E
        attributes[.isInvisible] = false
        attributes[.server] = "example.com"
        attributes[.internetProtocol] = .https
        attributes[.authenticationType] = .httpBasic
        attributes[.port] = 8443

        #expect(attributes[.label] == "label")
        #expect(attributes[.accessGroup] == group)
        #expect(attributes[.synchronizable] == true)
        #expect(attributes[.account] == "account")
        #expect(attributes[.creator] == 0x4B_43_48_4E)
        #expect(attributes[.isInvisible] == false)
        #expect(attributes[.server] == "example.com")
        #expect(attributes[.internetProtocol] == .https)
        #expect(attributes[.authenticationType] == .httpBasic)
        #expect(attributes[.port] == 8443)

        #expect(attributes.storage[kSecAttrProtocol as String] == .string("htps"))
        #expect(attributes.storage[kSecAttrPort as String] == .integer(8443))
        #expect(attributes.storage[kSecAttrCreator as String] == .integer(0x4B_43_48_4E))
    }

    @Test func genericDataRoundTrips() {
        var attributes = Attributes<GenericPassword>()
        attributes[.generic] = Data([1, 2, 3])
        #expect(attributes[.generic] == Data([1, 2, 3]))
        attributes[.generic] = nil
        #expect(attributes[.generic] == nil)
        #expect(attributes.isEmpty)
    }

    @Test func readOnlyKeysDecodeFrameworkValues() {
        let created = Date(timeIntervalSince1970: 1_000)
        let attributes = Attributes<GenericPassword>(secDictionary: [
            kSecClass as String: .string("genp"),
            kSecAttrCreationDate as String: .date(created),
            kSecAttrService as String: .string("service"),
        ])
        #expect(attributes[.creationDate] == created)
        #expect(attributes[.modificationDate] == nil)
        #expect(attributes[.service] == "service")
        #expect(attributes.storage[kSecClass as String] == nil)
    }

    @Test func mismatchedStoredTypeDecodesAsNil() {
        let attributes = Attributes<InternetPassword>(secDictionary: [kSecAttrPort as String: .string("not a number")])
        #expect(attributes[.port] == nil)
    }

    @Test func fourCharacterCodesKeepTheirTopBit() {
        // Valid on every platform, including watchOS arm64_32 where `Int` is 32 bits.
        var attributes = Attributes<GenericPassword>()
        attributes[.creator] = UInt32.max
        attributes[.type] = 0x8000_0001
        #expect(attributes[.creator] == UInt32.max)
        #expect(attributes[.type] == 0x8000_0001)
        #expect(attributes.storage[kSecAttrCreator as String] == .integer(Int64(UInt32.max)))
    }

    @Test func fourCharacterCodesOutsideUInt32DecodeAsNil() {
        let attributes = Attributes<GenericPassword>(secDictionary: [
            kSecAttrCreator as String: .integer(-1),
            kSecAttrType as String: .integer(Int64(UInt32.max) + 1),
        ])
        #expect(attributes[.creator] == nil)
        #expect(attributes[.type] == nil)
    }

    @Test func keysCompareByRawKey() {
        #expect(AttributeKey<GenericPassword, String>.label == .label)
        #expect(AttributeKey<GenericPassword, String>.label != .account)
        #expect(AttributeKey<GenericPassword, String>.label.hashValue == AttributeKey<GenericPassword, String>.label.hashValue)
    }
}
