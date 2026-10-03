//
//  KeychainResultParsingTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

/// Checks how a `Keychain` turns framework results into model values.
@Suite struct KeychainResultParsingTests {
    private let created = Date(timeIntervalSince1970: 1_000)

    private var itemDictionary: SecValue {
        .dictionary([
            kSecClass as String: .string("genp"),
            kSecAttrService as String: .string("service"),
            kSecAttrAccount as String: .string("account"),
            kSecAttrCreationDate as String: .date(created),
            kSecValueData as String: .data(Data("secret".utf8)),
            kSecValuePersistentRef as String: .data(Data([7])),
        ])
    }

    @Test func itemSeparatesDataFromAttributes() throws {
        let item: Item<GenericPassword> = try Keychain.item(from: itemDictionary)
        #expect(item.data == Data("secret".utf8))
        #expect(item.service == "service")
        #expect(item.creationDate == created)
        #expect(item.attributes.storage[kSecValueData as String] == nil)
        #expect(item.attributes.storage[kSecValuePersistentRef as String] == nil)
        #expect(item.attributes.storage[kSecClass as String] == nil)
    }

    @Test func attributesDropNonAttributeEntries() throws {
        let attributes: Attributes<GenericPassword> = try Keychain.attributes(from: itemDictionary)
        #expect(attributes.account == "account")
        #expect(attributes.storage[kSecValueData as String] == nil)
    }

    @Test func attributesAndReferenceSplitTheAllEntry() throws {
        let (attributes, reference): (Attributes<GenericPassword>, PersistentReference) = try Keychain.attributesAndReference(from: itemDictionary)
        #expect(attributes.service == "service")
        #expect(reference == PersistentReference(rawValue: Data([7])))
    }

    @Test func bareValuesDecode() throws {
        #expect(try Keychain.data(from: .data(Data([1]))) == Data([1]))
        #expect(try Keychain.persistentReference(from: .data(Data([2]))) == PersistentReference(rawValue: Data([2])))
        #expect(try Keychain.persistentReference(fromAdd: .data(Data([3]))) == PersistentReference(rawValue: Data([3])))
    }

    @Test func unexpectedShapesAreDecodingFailures() {
        let failure = KeychainError(code: .decodingFailed)
        #expect(throws: failure) { try Keychain.item(from: .data(Data())) as Item<GenericPassword> }
        #expect(throws: failure) { try Keychain.attributes(from: .string("x")) as Attributes<GenericPassword> }
        #expect(throws: failure) { try Keychain.attributesAndReference(from: .dictionary([:])) as (Attributes<GenericPassword>, PersistentReference) }
        #expect(throws: failure) { try Keychain.data(from: .bool(true)) }
        #expect(throws: failure) { try Keychain.persistentReference(fromAdd: nil) }
    }
}
