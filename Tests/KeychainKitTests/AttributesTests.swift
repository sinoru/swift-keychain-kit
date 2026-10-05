//
//  AttributesTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

@Suite struct AttributesTests {
    @Test func accessibleProtectionIsStoredUnderTheAccessibleKey() {
        var attributes = Attributes<GenericPassword>()
        attributes.protection = .accessible(.afterFirstUnlock)
        #expect(attributes.protection == .accessible(.afterFirstUnlock))
        #expect(attributes.secDictionary == [SecItemKey(kSecAttrAccessible): .string(kSecAttrAccessibleAfterFirstUnlock as String)])
    }

    @Test func accessControlProtectionIsEmittedAsAnObject() throws {
        let control = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
        var attributes = Attributes<GenericPassword>()
        attributes.protection = .accessControl(control)

        #expect(attributes.protection == .accessControl(control))
        #expect(attributes.secDictionary[SecItemKey(kSecAttrAccessible)] == nil)
        guard case .object(let object)? = attributes.secDictionary[SecItemKey(kSecAttrAccessControl)] else {
            Issue.record("expected an access control object")
            return
        }
        #expect(CFGetTypeID(object.reference) == SecAccessControlGetTypeID())
    }

    @Test func settingOneProtectionFormClearsTheOther() throws {
        var attributes = Attributes<GenericPassword>()
        attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked))
        attributes.protection = .accessible(.whenUnlocked)
        #expect(attributes.secDictionary[SecItemKey(kSecAttrAccessControl)] == nil)
        #expect(attributes.protection == .accessible(.whenUnlocked))

        attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked))
        #expect(attributes.secDictionary[SecItemKey(kSecAttrAccessible)] == nil)

        attributes.protection = nil
        #expect(attributes.isEmpty)
    }

    @Test func accessControlReadBackFromTheFrameworkIsOpaque() throws {
        let control = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
        let attributes = Attributes<GenericPassword>(secDictionary: [SecItemKey(kSecAttrAccessControl): .object(control.secObject)])
        guard case .accessControl(let opaque)? = attributes.protection else {
            Issue.record("expected an access control, got \(String(describing: attributes.protection))")
            return
        }
        #expect(opaque.accessibility == nil)
        #expect(opaque.flags == nil)
        #expect(opaque.secObject == control.secObject)
        #expect(opaque != control)
    }

    /// The data protection keychain returns both keys for every item; only the object goes back.
    @Test func accessControlReadBackNextToAnAccessibilityCarriesIt() throws {
        let control = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
        let attributes = Attributes<GenericPassword>(secDictionary: [
            SecItemKey(kSecAttrAccessible): .string(kSecAttrAccessibleWhenUnlocked as String),
            SecItemKey(kSecAttrAccessControl): .object(control.secObject),
        ])
        guard case .accessControl(let opaque)? = attributes.protection else {
            Issue.record("expected an access control, got \(String(describing: attributes.protection))")
            return
        }
        #expect(opaque.accessibility == .whenUnlocked)
        #expect(opaque.flags == nil)
        #expect(attributes.secDictionary == [SecItemKey(kSecAttrAccessControl): .object(control.secObject)])
    }

    @Test func protectionReportsTheAccessibilityOfEitherForm() throws {
        let control = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
        #expect(Protection.accessible(.afterFirstUnlock).accessibility == .afterFirstUnlock)
        #expect(Protection.accessControl(control).accessibility == .whenUnlocked)
        #expect(Protection.accessControl(AccessControl(opaque: control.secObject, accessibility: nil)).accessibility == nil)
    }

    @Test func attributesAreHashableByContent() throws {
        var first = Attributes<GenericPassword>()
        first.service = "service"
        first.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .userPresence))
        var second = Attributes<GenericPassword>()
        second.service = "service"
        second.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .userPresence))
        #expect(first == second)
        #expect(first.hashValue == second.hashValue)
    }
}
