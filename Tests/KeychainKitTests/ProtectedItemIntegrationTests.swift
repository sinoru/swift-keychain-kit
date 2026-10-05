//
//  ProtectedItemIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

/// Searches for generic passwords with the raw request, so each test states the exact keys it
/// measures.
private struct PasswordSearch {
    let service: String

    func callAsFunction(account: String? = nil, _ extra: SecDictionary) throws(KeychainError) -> SecValue? {
        var query: SecDictionary = [
            SecItemKey(kSecClass): .string(kSecClassGenericPassword as String),
            SecItemKey(kSecAttrService): .string(service),
            SecItemKey(kSecUseDataProtectionKeychain): .bool(true),
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
/// No protected item is involved, so this runs wherever the keychain is reachable. That includes
/// a Mac, when the tests are hosted in an app signed by a team: the passwords then go into the
/// data protection keychain of the person running the tests, in the test app's access group,
/// and are removed again.
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
        #expect(Set(try keychain.fetch(matching: Query<GenericPassword>(service: service)).compactMap(\.password)) == ["1", "2"])
    }
}

#if canImport(LocalAuthentication) && !os(tvOS) && !os(macOS) && !targetEnvironment(macCatalyst)
import CryptoTokenKit
import LocalAuthentication

/// Whether this device enforces an access control that asks for the user.
///
/// A simulator accepts such an access control and then ignores it: the item is read with no
/// prompt, even where `LAContext.canEvaluatePolicy(_:error:)` says the device can authenticate
/// its owner (measured on the iOS 27 simulator). So the probe asks the keychain itself: it adds
/// a password protected by user presence, reads its data with interaction not allowed, and
/// removes it. Only a keychain that refuses that read says anything about a protected item.
enum DeviceAuthentication {
    static let isEnforced: Bool = {
        let keychain = Keychain()
        let service = "dev.sinoru.KeychainKit.tests.probe.protected"
        let probe = Query<GenericPassword>(service: service)
        try? keychain.delete(matching: probe)
        defer { try? keychain.delete(matching: probe) }
        do throws(KeychainError) {
            var item = Item(service: service, account: "probe", password: "probe")
            item.attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .userPresence))
            try keychain.add(item)

            let context = LAContext()
            context.interactionNotAllowed = true
            _ = try PasswordSearch(service: service)([
                SecItemKey(kSecReturnData): .bool(true),
                SecItemKey(kSecUseAuthenticationContext): .object(SecObject(context)),
            ])
            return false
        } catch {
            return error.code == .interactionNotAllowed
        }
    }()
}

/// Whether the person running the tests agreed to answer an authentication prompt.
///
/// Set `KEYCHAINKIT_ALLOW_PROMPT` in the scheme's test environment, or pass
/// `TEST_RUNNER_KEYCHAINKIT_ALLOW_PROMPT=1` to `xcodebuild`.
enum AuthenticationPrompt {
    static let isAllowed = ProcessInfo.processInfo.environment["KEYCHAINKIT_ALLOW_PROMPT"] != nil
}

/// What the data protection keychain does with a password that asks for the user.
///
/// Each test adds one password anyone can read and one protected by user presence, under a
/// service of its own, and removes both. Adding and deleting a protected item asks for nothing.
/// Only `dataFetchAsksForTheUser` shows a prompt, and it runs only when asked to.
@Suite(.enabled(
    if: DataProtectionKeychain.isReachable && DeviceAuthentication.isEnforced,
    "A protected item needs a host app and a keychain that enforces its access control.",
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
            try keychain.fetchFirstAttributes(matching: query)
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
        #expect(try keychain.fetch(matching: query).map(\.account) == ["open"])
    }

    @Test func allWithoutInteractionIsRefused() throws {
        defer { try? keychain.delete(matching: passwords) }
        try addOpenAndProtectedPasswords()

        let context = LAContext()
        context.interactionNotAllowed = true
        var query = passwords
        query.authenticationContext = AuthenticationContext(context)
        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try keychain.fetch(matching: query)
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

/// What a Secure Enclave key that asks for the user reports when the user does not answer.
///
/// An operation on such a key hands back the token's own error, not an `OSStatus`. Each test
/// records the domain and code of that raw error next to the code `KeyReference` makes of it.
/// Each generates a key under a tag of its own and removes it. Generating and deleting ask for
/// nothing. Only `cancelledSignatureIsUserCanceled` shows a prompt, and it runs only when
/// asked to.
///
/// Biometry that fails to match is not among them: the prompt keeps offering another try and
/// ends only when the person cancels, which is the cancellation again (measured with Face ID
/// on iPadOS 27).
@Suite(.enabled(
    if: DataProtectionKeychain.isReachable && DeviceAuthentication.isEnforced,
    "A protected key needs a host app and a keychain that enforces its access control.",
))
struct ProtectedKeyIntegrationTests {
    private let keychain = Keychain()
    private let tag = Data(UUID().uuidString.utf8)
    private let digest = Data(repeating: 0xAB, count: 32)

    private var keys: Query<CryptographicKey> {
        var query = Query<CryptographicKey>()
        query.applicationTag = tag
        return query
    }

    /// The domain and code of the error `SecKeyCreateSignature` reports for `key`, or `nil`
    /// when it signs.
    private func rawSignatureFailure(of key: KeyReference) -> RawFailure? {
        var error: Unmanaged<CFError>?
        let signature = unsafe SecKeyCreateSignature(
            key.reference,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error,
        )
        guard signature == nil, let failure = unsafe error?.takeRetainedValue() else {
            return nil
        }
        return RawFailure(domain: CFErrorGetDomain(failure) as String, code: CFErrorGetCode(failure))
    }

    private struct RawFailure: Equatable {
        var domain: String
        var code: Int
    }

    @Test func signatureWithoutInteractionIsRefused() throws {
        defer { try? keychain.delete(matching: keys) }
        let context = LAContext()
        context.interactionNotAllowed = true
        let key = try keychain.generateSecureEnclaveKey(
            applicationTag: tag,
            constraints: .userPresence,
            authenticationContext: AuthenticationContext(context),
        )

        #expect(rawSignatureFailure(of: key) == RawFailure(domain: LAErrorDomain, code: LAError.Code.notInteractive.rawValue))
        #expect(throws: KeychainError(code: .interactionNotAllowed)) {
            try key.signature(for: digest, using: .ecdsaSignatureDigestX962SHA256)
        }
    }

    /// Cancel both times the device asks.
    ///
    /// The key asks for the passcode alone: biometry matches the person holding the device
    /// before they can cancel.
    @Test(.enabled(if: AuthenticationPrompt.isAllowed, "Set KEYCHAINKIT_ALLOW_PROMPT to answer a prompt."))
    func cancelledSignatureIsUserCanceled() throws {
        defer { try? keychain.delete(matching: keys) }
        let context = LAContext()
        #if !os(watchOS)
        context.localizedReason = "Cancel this prompt."
        #endif
        let key = try keychain.generateSecureEnclaveKey(
            applicationTag: tag,
            constraints: .devicePasscode,
            authenticationContext: AuthenticationContext(context),
        )

        #expect(rawSignatureFailure(of: key) == RawFailure(domain: LAErrorDomain, code: LAError.Code.userCancel.rawValue))
        #expect(throws: KeychainError(code: .userCanceled)) {
            try key.signature(for: digest, using: .ecdsaSignatureDigestX962SHA256)
        }
    }

    /// The token session, not LocalAuthentication, reports a context that was invalidated: the
    /// one failure of a Secure Enclave key here that arrives in the CryptoTokenKit domain, as a
    /// communication error. It needs nobody to answer a prompt.
    @Test func signatureWithInvalidatedContextIsInternalError() throws {
        defer { try? keychain.delete(matching: keys) }
        let context = LAContext()
        let key = try keychain.generateSecureEnclaveKey(
            applicationTag: tag,
            constraints: .userPresence,
            authenticationContext: AuthenticationContext(context),
        )
        context.invalidate()

        #expect(rawSignatureFailure(of: key) == RawFailure(domain: TKErrorDomain, code: TKError.Code.communicationError.rawValue))
        #expect(throws: KeychainError(code: .internalError)) {
            try key.signature(for: digest, using: .ecdsaSignatureDigestX962SHA256)
        }
    }
}
#endif
