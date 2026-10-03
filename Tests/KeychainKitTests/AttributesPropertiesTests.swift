//
//  AttributesPropertiesTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

/// Each attribute property must read and write the right `kSecAttr*` key with the right type.
@Suite struct AttributesPropertiesTests {
    @Test func propertiesStoreUnderTheirSecurityKeys() throws {
        let group = try #require(AccessGroup(rawValue: "TEAM.group"))
        var generic = Attributes<GenericPassword>()
        generic.label = "label"
        generic.accessGroup = group
        generic.synchronizable = true
        generic.account = "account"
        generic.itemDescription = "description"
        generic.comment = "comment"
        generic.creator = 0x4B_43_48_4E
        generic.type = 0x5459_5045
        generic.isInvisible = true
        generic.isNegative = false
        generic.service = "service"
        generic.generic = Data([1, 2, 3])
        #expect(generic.storage == [
            kSecAttrLabel as String: .string("label"),
            kSecAttrAccessGroup as String: .string("TEAM.group"),
            kSecAttrSynchronizable as String: .bool(true),
            kSecAttrAccount as String: .string("account"),
            kSecAttrDescription as String: .string("description"),
            kSecAttrComment as String: .string("comment"),
            kSecAttrCreator as String: .integer(0x4B_43_48_4E),
            kSecAttrType as String: .integer(0x5459_5045),
            kSecAttrIsInvisible as String: .bool(true),
            kSecAttrIsNegative as String: .bool(false),
            kSecAttrService as String: .string("service"),
            kSecAttrGeneric as String: .data(Data([1, 2, 3])),
        ])

        var internet = Attributes<InternetPassword>()
        internet.server = "example.com"
        internet.securityDomain = "domain"
        internet.path = "/api"
        internet.internetProtocol = .https
        internet.authenticationType = .httpBasic
        internet.port = 8443
        #expect(internet.storage == [
            kSecAttrServer as String: .string("example.com"),
            kSecAttrSecurityDomain as String: .string("domain"),
            kSecAttrPath as String: .string("/api"),
            kSecAttrProtocol as String: .string(kSecAttrProtocolHTTPS as String),
            kSecAttrAuthenticationType as String: .string(kSecAttrAuthenticationTypeHTTPBasic as String),
            kSecAttrPort as String: .integer(8443),
        ])
    }

    @Test func propertiesReadBackWhatWasWritten() throws {
        var attributes = Attributes<InternetPassword>()
        let group = try #require(AccessGroup(rawValue: "TEAM.group"))
        attributes.label = "label"
        attributes.accessGroup = group
        attributes.synchronizable = true
        attributes.account = "account"
        attributes.creator = 0x4B_43_48_4E
        attributes.isInvisible = false
        attributes.server = "example.com"
        attributes.internetProtocol = .https
        attributes.authenticationType = .httpBasic
        attributes.port = 8443

        #expect(attributes.label == "label")
        #expect(attributes.accessGroup == group)
        #expect(attributes.synchronizable == true)
        #expect(attributes.account == "account")
        #expect(attributes.creator == 0x4B_43_48_4E)
        #expect(attributes.isInvisible == false)
        #expect(attributes.server == "example.com")
        #expect(attributes.internetProtocol == .https)
        #expect(attributes.authenticationType == .httpBasic)
        #expect(attributes.port == 8443)
    }

    @Test func settingNilRemovesTheEntry() {
        var attributes = Attributes<GenericPassword>()
        attributes.generic = Data([1, 2, 3])
        #expect(attributes.generic == Data([1, 2, 3]))
        attributes.generic = nil
        #expect(attributes.generic == nil)
        #expect(attributes.isEmpty)
    }

    @Test func frameworkSetDatesAreReadOnlyProperties() {
        let created = Date(timeIntervalSince1970: 1_000)
        let attributes = Attributes<GenericPassword>(secDictionary: [
            kSecClass as String: .string("genp"),
            kSecAttrCreationDate as String: .date(created),
            kSecAttrService as String: .string("service"),
        ])
        #expect(attributes.creationDate == created)
        #expect(attributes.modificationDate == nil)
        #expect(attributes.service == "service")
        #expect(attributes.storage[kSecClass as String] == nil)
    }

    @Test func mismatchedStoredTypeReadsAsNil() {
        let attributes = Attributes<InternetPassword>(secDictionary: [kSecAttrPort as String: .string("not a number")])
        #expect(attributes.port == nil)
    }

    @Test func fourCharacterCodesKeepTheirTopBit() {
        // Valid on every platform, including watchOS arm64_32 where `Int` is 32 bits.
        var attributes = Attributes<GenericPassword>()
        attributes.creator = UInt32.max
        attributes.type = 0x8000_0001
        #expect(attributes.creator == UInt32.max)
        #expect(attributes.type == 0x8000_0001)
        #expect(attributes.storage[kSecAttrCreator as String] == .integer(Int64(UInt32.max)))
    }

    @Test func fourCharacterCodesOutsideUInt32ReadAsNil() {
        let attributes = Attributes<GenericPassword>(secDictionary: [
            kSecAttrCreator as String: .integer(-1),
            kSecAttrType as String: .integer(Int64(UInt32.max) + 1),
        ])
        #expect(attributes.creator == nil)
        #expect(attributes.type == nil)
    }

    @Test func booleansReadFromBooleanOrZeroOneIntegers() {
        func read(_ value: SecValue) -> Bool? {
            Attributes<GenericPassword>(secDictionary: [kSecAttrSynchronizable as String: value]).synchronizable
        }
        #expect(read(.bool(true)) == true)
        #expect(read(.bool(false)) == false)
        #expect(read(.integer(1)) == true)
        #expect(read(.integer(0)) == false)
        #expect(read(.integer(2)) == nil)
        #expect(read(.integer(-1)) == nil)
        #expect(read(.string("1")) == nil)
    }

    @Test func itemAndQueryForwardToAttributes() {
        var item = Item<InternetPassword>()
        item.server = "example.com"
        item.port = 443
        #expect(item.attributes.server == "example.com")
        #expect(item.port == 443)
        #expect(item.creationDate == nil)

        var query = Query<GenericPassword>()
        query.service = "service"
        #expect(query.attributes.service == "service")
        query.attributes.account = "account"
        #expect(query.account == "account")
    }
}
