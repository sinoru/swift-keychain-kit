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
            SecItemKey(kSecClass): .string("genp"),
            SecItemKey(kSecAttrService): .string("service"),
            SecItemKey(kSecAttrAccount): .string("account"),
            SecItemKey(kSecAttrCreationDate): .date(created),
            SecItemKey(kSecValueData): .data(Data("secret".utf8)),
            SecItemKey(kSecValuePersistentRef): .data(Data([7])),
        ])
    }

    @Test func itemSeparatesDataFromAttributes() throws {
        let item: Item<GenericPassword> = try Keychain.item(from: itemDictionary)
        #expect(item.data == Data("secret".utf8))
        #expect(item.service == "service")
        #expect(item.creationDate == created)
        #expect(item.attributes.storage[SecItemKey(kSecValueData)] == nil)
        #expect(item.attributes.storage[SecItemKey(kSecValuePersistentRef)] == nil)
        #expect(item.attributes.storage[SecItemKey(kSecClass)] == nil)
    }

    @Test func attributesDropNonAttributeEntries() throws {
        let attributes: Attributes<GenericPassword> = try Keychain.attributes(from: itemDictionary)
        #expect(attributes.account == "account")
        #expect(attributes.storage[SecItemKey(kSecValueData)] == nil)
    }

    #if os(macOS)
    @Test func attributesAndReferenceSplitTheAllEntry() throws {
        let (attributes, reference): (Attributes<GenericPassword>, PersistentReference) = try Keychain.attributesAndReference(from: itemDictionary)
        #expect(attributes.service == "service")
        #expect(reference == PersistentReference(rawValue: Data([7])))
        #expect(throws: KeychainError(code: .decodingFailed)) {
            try Keychain.attributesAndReference(from: .dictionary([:])) as (Attributes<GenericPassword>, PersistentReference)
        }
    }
    #endif

    @Test func bareValuesDecode() throws {
        #expect(try Keychain.data(from: .data(Data([1]))) == Data([1]))
        #expect(try Keychain.persistentReference(from: .data(Data([2]))) == PersistentReference(rawValue: Data([2])))
        #expect(try Keychain.persistentReference(fromAdd: .data(Data([3]))) == PersistentReference(rawValue: Data([3])))
    }

    @Test func unexpectedShapesAreDecodingFailures() {
        let failure = KeychainError(code: .decodingFailed)
        #expect(throws: failure) { try Keychain.item(from: .data(Data())) as Item<GenericPassword> }
        #expect(throws: failure) { try Keychain.attributes(from: .string("x")) as Attributes<GenericPassword> }
        #expect(throws: failure) { try Keychain.data(from: .bool(true)) }
        #expect(throws: failure) { try Keychain.persistentReference(fromAdd: nil) }
    }
}
