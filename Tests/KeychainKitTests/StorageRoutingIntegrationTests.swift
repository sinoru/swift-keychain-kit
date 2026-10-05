//
//  StorageRoutingIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
import Foundation
import Security
import Testing

@testable import KeychainKit

/// Which keychain a call reaches on a Mac, in a process that can use both.
///
/// Only an entitled process shows the difference: without an entitlement the framework drops
/// the data protection half of a call that names neither keychain, so the package's own test
/// run sees the file-based keychain alone. This runs when the tests are hosted in an app signed
/// by a team.
///
/// The password tests put one item in the data protection keychain and one in the default
/// file-based keychain of the person running the tests, the login keychain, under a service of
/// their own, and remove both again. The tests of what the framework drops use a temporary
/// keychain.
///
/// The tests run one at a time. Run together, `fetch(matching:)` on the login keychain now and
/// then came back empty while another test was at work, and returned the item when asked again
/// (measured on macOS 27).
@Suite(.enabled(if: DataProtectionKeychain.isReachable, "The data protection keychain needs a host app."), .serialized)
struct StorageRoutingIntegrationTests {
    private let dataProtection = Keychain()
    private let fileBased = Keychain(storage: .fileBased())
    private let service = "dev.sinoru.KeychainKit.tests.\(UUID().uuidString)"
    private let tag = Data(UUID().uuidString.utf8)

    private var passwords: Query<GenericPassword> {
        Query(service: service, account: "account")
    }

    private var keys: Query<CryptographicKey> {
        var query = Query<CryptographicKey>()
        query.applicationTag = tag
        return query
    }

    /// The same password in both keychains, told apart by its data.
    private func addToBoth() throws {
        try dataProtection.add(Item(service: service, account: "account", password: "data protection"))
        try fileBased.add(Item(service: service, account: "account", password: "file-based"))
    }

    private func removeFromBoth() {
        try? dataProtection.delete(matching: passwords)
        try? fileBased.delete(matching: passwords)
    }

    /// The search, update, and delete a `Keychain` builds, with the keychain left unnamed.
    private var unnamed: SecDictionary {
        var dictionary = passwords.secDictionary
        dictionary[SecItemKey(kSecUseDataProtectionKeychain)] = nil
        return dictionary
    }

    // MARK: A call that names neither keychain

    @Test func unnamedSearchReachesBothKeychainsAndPrefersDataProtection() throws {
        defer { removeFromBoth() }
        try addToBoth()

        let first = try Keychain.secItemCopyMatching(unnamed.merging([SecItemKey(kSecReturnData): .bool(true)]) { _, new in new })
        #expect(first == .data(Data("data protection".utf8)))

        let all = try Keychain.secItemCopyMatching(unnamed.merging([
            SecItemKey(kSecReturnAttributes): .bool(true),
            SecItemKey(kSecMatchLimit): .string(kSecMatchLimitAll as String),
        ]) { _, new in new })
        guard case .array(let values)? = all else {
            Issue.record("expected an array, got \(String(describing: all))")
            return
        }
        #expect(values.count == 2)
    }

    @Test func unnamedUpdateChangesBothKeychains() throws {
        defer { removeFromBoth() }
        try addToBoth()

        try Keychain.secItemUpdate(unnamed, with: [SecItemKey(kSecValueData): .data(Data("changed".utf8))])
        #expect(try dataProtection.fetchFirst(matching: passwords)?.password == "changed")
        #expect(try fileBased.fetchFirst(matching: passwords)?.password == "changed")
    }

    @Test func unnamedDeleteRemovesFromBothKeychains() throws {
        defer { removeFromBoth() }
        try addToBoth()

        try Keychain.secItemDelete(unnamed)
        #expect(try dataProtection.fetchFirst(matching: passwords) == nil)
        #expect(try fileBased.fetchFirst(matching: passwords) == nil)
    }

    // MARK: File-based storage

    @Test func fileBasedStorageLeavesTheDataProtectionKeychainAlone() throws {
        defer { removeFromBoth() }
        try addToBoth()

        #expect(try fileBased.fetchFirst(matching: passwords)?.password == "file-based")
        #expect(try fileBased.fetch(matching: passwords).map(\.password) == ["file-based"])
        #expect(try fileBased.fetchAttributes(matching: passwords).count == 1)

        try fileBased.update(matching: passwords, with: Item(data: Data("changed".utf8)))
        #expect(try fileBased.fetchFirst(matching: passwords)?.password == "changed")
        #expect(try dataProtection.fetchFirst(matching: passwords)?.password == "data protection")

        try fileBased.delete(matching: passwords)
        #expect(try fileBased.fetchFirst(matching: passwords) == nil)
        #expect(try dataProtection.fetchFirst(matching: passwords)?.password == "data protection")
    }

    // MARK: What the framework drops

    /// Why `Storage.validate(_:)` refuses an access control itself: told to stay out of the data
    /// protection keychain, the framework stores the item without one and reports success.
    @Test func frameworkStoresAPasswordWithoutItsAccessControl() throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        var item = Item(service: service, account: "account", password: "secret")
        item.attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked))
        let confined = keychain.addDictionary(for: item)

        var unnamed = confined
        unnamed[SecItemKey(kSecUseDataProtectionKeychain)] = nil
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try Keychain.secItemAdd(unnamed)
        }

        try Keychain.secItemAdd(confined)
        let stored = try #require(try keychain.fetchFirst(matching: passwords))
        #expect(stored.password == "secret")
        #expect(stored.attributes.protection == nil)
        #expect(try dataProtection.fetchFirst(matching: passwords) == nil)
    }

    /// The same for key generation, which also reads the key that names the keychain.
    @Test func frameworkGeneratesAKeyWithoutItsAccessControl() throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        defer { try? dataProtection.delete(matching: keys) }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        var attributes = Attributes<CryptographicKey>()
        attributes.applicationTag = tag
        attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked))
        let confined = keychain.generationDictionary(for: .ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)

        var unnamed = confined
        unnamed[SecItemKey(kSecUseDataProtectionKeychain)] = nil
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try KeyReference(generatingWith: unnamed)
        }

        _ = try KeyReference(generatingWith: confined)
        let stored = try #require(try keychain.fetchFirstAttributes(matching: keys))
        #expect(stored.protection == nil)
        #expect(try dataProtection.fetchFirstAttributes(matching: keys) == nil)
    }

    /// A key asked of the Secure Enclave is generated in software instead.
    @Test func frameworkGeneratesASecureEnclaveKeyInSoftware() throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        defer { try? dataProtection.delete(matching: keys) }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        var attributes = Attributes<CryptographicKey>()
        attributes.applicationTag = tag
        attributes.tokenID = .secureEnclave
        let confined = keychain.generationDictionary(for: .ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)

        _ = try KeyReference(generatingWith: confined)
        let stored = try #require(try keychain.fetchFirstAttributes(matching: keys))
        #expect(stored.tokenID == nil)
        #expect(try dataProtection.fetchFirstAttributes(matching: keys) == nil)
    }
}
#endif
