//
//  ProtectedItemIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if canImport(LocalAuthentication) && !os(tvOS) && !os(macOS) && !targetEnvironment(macCatalyst)
import Foundation
import LocalAuthentication
import Security
import Testing

@testable import KeychainKit

/// Whether this device enforces an access control that asks for the user.
///
/// A simulator with no passcode and no enrolled biometrics accepts such an access control and
/// then ignores it: the item is read with no prompt (measured on the iOS 27 simulator). Only a
/// device with a passcode, or a simulator with Face ID enrolled, says anything about a protected
/// item.
enum DeviceAuthentication {
    static let isEnforced = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
}

/// Whether the person running the tests agreed to answer an authentication prompt.
///
/// Set `KEYCHAINKIT_ALLOW_PROMPT` in the scheme's test environment, or pass
/// `TEST_RUNNER_KEYCHAINKIT_ALLOW_PROMPT=1` to `xcodebuild`.
enum AuthenticationPrompt {
    static let isAllowed = ProcessInfo.processInfo.environment["KEYCHAINKIT_ALLOW_PROMPT"] != nil
}

/// Searches for generic passwords with the raw request, so each test states the exact keys it
/// measures.
private struct PasswordSearch {
    let service: String

    func callAsFunction(account: String? = nil, _ extra: SecDictionary) throws(KeychainError) -> SecValue? {
        var query: SecDictionary = [
            SecItemKey(kSecClass): .string(kSecClassGenericPassword as String),
            SecItemKey(kSecAttrService): .string(service),
        ]
        if let account {
            query[SecItemKey(kSecAttrAccount)] = .string(account)
        }
        return try Keychain.secItemCopyMatching(query.merging(extra) { _, new in new })
    }

    /// The account and data of each element of a search for every match.
    static func accountsAndData(in result: SecValue?) -> [String: Data?] {
        guard case .array(let values)? = result else {
            return [:]
        }
        var found: [String: Data?] = [:]
        for case .dictionary(let dictionary) in values {
            guard case .string(let account)? = dictionary[SecItemKey(kSecAttrAccount)] else {
                continue
            }
            if case .data(let data)? = dictionary[SecItemKey(kSecValueData)] {
                found[account] = data
            } else {
                found[account] = Data?.none
            }
        }
        return found
    }
}

/// What the data protection keychain does when one search asks for the data of every password.
///
/// Apple documents `kSecReturnData` with `kSecMatchLimitAll` as unavailable for password items.
/// No protected item is involved, so this runs wherever the keychain is reachable.
@Suite(.enabled(if: DataProtectionKeychain.isReachable, "The data protection keychain needs a host app."))
struct PasswordDataSearchIntegrationTests {
    private let keychain = Keychain()
    private let service = "dev.sinoru.KeychainKit.tests.\(UUID().uuidString)"

    @Test func oneSearchReturnsTheDataOfEveryPassword() throws {
        defer { try? keychain.delete(matching: Query<GenericPassword>(service: service)) }

        try keychain.add(Item(service: service, account: "one", password: "1"))
        try keychain.add(Item(service: service, account: "two", password: "2"))

        let result = try PasswordSearch(service: service)([
            SecItemKey(kSecReturnAttributes): .bool(true),
            SecItemKey(kSecReturnData): .bool(true),
            SecItemKey(kSecMatchLimit): .string(kSecMatchLimitAll as String),
        ])
        #expect(PasswordSearch.accountsAndData(in: result) == ["one": Data("1".utf8), "two": Data("2".utf8)])
    }
}

/// What the data protection keychain does with a password that asks for the user.
///
/// Each test adds one password anyone can read and one protected by user presence, under a
/// service of its own, and removes both. Adding and deleting a protected item asks for nothing.
/// Only `dataFetchAsksForTheUser` shows a prompt, and it runs only when asked to.
@Suite(.enabled(
    if: DataProtectionKeychain.isReachable && DeviceAuthentication.isEnforced,
    "A protected item needs a host app and a device with a passcode or enrolled biometrics.",
))
struct ProtectedItemIntegrationTests {
    private let keychain = Keychain()
    private let service = "dev.sinoru.KeychainKit.tests.\(UUID().uuidString)"

    private var search: PasswordSearch {
        PasswordSearch(service: service)
    }

    private var passwords: Query<GenericPassword> {
        Query(service: service)
    }

    private var skipping: SecDictionary {
        [SecItemKey(kSecUseAuthenticationUI): .string(kSecUseAuthenticationUISkip as String)]
    }

    /// An authentication context that fails a call instead of prompting.
    private var withoutInteraction: SecDictionary {
        let context = LAContext()
        context.interactionNotAllowed = true
        return [SecItemKey(kSecUseAuthenticationContext): .object(SecObject(context))]
    }

    private var everyMatch: SecDictionary {
        [SecItemKey(kSecMatchLimit): .string(kSecMatchLimitAll as String)]
    }

    private func addOpenAndProtectedPasswords() throws {
        try keychain.add(Item(service: service, account: "open", password: "1"))
        var protected = Item(service: service, account: "protected", password: "2")
        protected.attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .userPresence))
        try keychain.add(protected)
    }

    // MARK: One item at a time

    /// Even a search that reads no data authenticates for a protected item.
    @Test func attributesSearchWithoutInteractionIsRefused() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try search([SecItemKey(kSecReturnAttributes): .bool(true)]
                .merging(everyMatch) { _, new in new }
                .merging(withoutInteraction) { _, new in new })
        }
    }

    @Test func attributesOfTheProtectedItemAreRefusedWithoutInteraction() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        let context = LAContext()
        context.interactionNotAllowed = true
        var query = Query<GenericPassword>(service: service, account: "protected")
        query.authenticationContext = AuthenticationContext(context)
        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try keychain.attributes(matching: query)
        }
    }

    /// The skip option leaves a protected item out even of a search that reads no data.
    @Test func attributesSearchThatSkipsLeavesTheProtectedItemOut() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        let result = try search([SecItemKey(kSecReturnAttributes): .bool(true)]
            .merging(everyMatch) { _, new in new }
            .merging(skipping) { _, new in new })
        #expect(Set(PasswordSearch.accountsAndData(in: result).keys) == ["open"])
    }

    @Test func dataFetchThatSkipsFindsNothing() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        #expect(throws: KeychainError(code: .itemNotFound)) {
            try search(account: "protected", [SecItemKey(kSecReturnData): .bool(true)]
                .merging(skipping) { _, new in new })
        }
    }

    @Test func dataFetchWithoutInteractionIsRefused() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try search(account: "protected", [SecItemKey(kSecReturnData): .bool(true)]
                .merging(withoutInteraction) { _, new in new })
        }
    }

    /// Authenticate when the device asks.
    @Test(.enabled(if: AuthenticationPrompt.isAllowed, "Set KEYCHAINKIT_ALLOW_PROMPT to answer a prompt."))
    func dataFetchAsksForTheUser() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        #expect(try search(account: "protected", [SecItemKey(kSecReturnData): .bool(true)]) == .data(Data("2".utf8)))
    }

    @Test func allThatSkipsLeavesTheProtectedItemOut() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        var query = passwords
        query.skipsItemsRequiringAuthentication = true
        #expect(try keychain.all(matching: query).map(\.account) == ["open"])
    }

    @Test func allWithoutInteractionIsRefused() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        let context = LAContext()
        context.interactionNotAllowed = true
        var query = passwords
        query.authenticationContext = AuthenticationContext(context)
        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try keychain.all(matching: query)
        }
    }

    // MARK: Every item in one search

    @Test func oneSearchForDataThatSkipsLeavesTheProtectedItemOut() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        let result = try search([SecItemKey(kSecReturnAttributes): .bool(true), SecItemKey(kSecReturnData): .bool(true)]
            .merging(everyMatch) { _, new in new }
            .merging(skipping) { _, new in new })
        #expect(PasswordSearch.accountsAndData(in: result) == ["open": Data("1".utf8)])
    }

    @Test func oneSearchForDataWithoutInteractionIsRefused() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try search([SecItemKey(kSecReturnAttributes): .bool(true), SecItemKey(kSecReturnData): .bool(true)]
                .merging(everyMatch) { _, new in new }
                .merging(withoutInteraction) { _, new in new })
        }
    }
}
#endif
