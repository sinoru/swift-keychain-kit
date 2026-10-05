//
//  DataProtectionIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Testing

import KeychainKit

/// Whether this process can use the data protection keychain.
///
/// A test bundle that runs in a host app can. One that runs in the bare `xctest` runner cannot:
/// signing the bundle with entitlements does not change that (measured on the iOS 27 simulator).
/// The package's own test runs are of the second kind, so the suites that need the keychain are
/// skipped there and run from `Xcode/KeychainKit.xcodeproj`, whose tests are hosted in an app.
///
/// The probe adds a password and removes it. A search does not tell the two apart on a Mac,
/// where one that has no access group to look in finds nothing without complaint and only the
/// add fails with `errSecMissingEntitlement` (measured on macOS 27).
enum DataProtectionKeychain {
    static let isReachable: Bool = {
        let keychain = Keychain()
        let probe = Query<GenericPassword>(service: "dev.sinoru.KeychainKit.tests.probe")
        defer { try? keychain.delete(matching: probe) }
        do throws(KeychainError) {
            try keychain.add(Item(service: "dev.sinoru.KeychainKit.tests.probe", account: "probe", password: ""))
            return true
        } catch {
            return error.code == .duplicateItem
        }
    }()
}

#if targetEnvironment(simulator)
/// Runs the public `Keychain` API against the data protection keychain of a simulator.
///
/// Only a simulator is used. Its keychain belongs to the simulated device, so nothing here can
/// reach the keychain of the person running the tests, which a hosted run on macOS could.
/// Each test works under a service or tag of its own and removes what it added.
@Suite(.enabled(if: DataProtectionKeychain.isReachable, "The data protection keychain needs a host app."))
struct DataProtectionIntegrationTests {
    private let keychain = Keychain()
    private let service = "dev.sinoru.KeychainKit.tests.\(UUID().uuidString)"
    private let tag = Data(UUID().uuidString.utf8)
    private let message = Data("message".utf8)

    private func passwords(account: String? = nil) -> Query<GenericPassword> {
        Query(service: service, account: account)
    }

    private func keys(label: String? = nil) -> Query<CryptographicKey> {
        var query = Query<CryptographicKey>()
        query.applicationTag = tag
        query.label = label
        return query
    }

    private func keyItem(label: String) throws -> Item<CryptographicKey> {
        var item = Item<CryptographicKey>(reference: try KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256))
        item.applicationTag = tag
        item.label = label
        return item
    }

    // MARK: Passwords

    @Test func passwordIsAddedFoundUpdatedAndDeleted() throws {
        defer { try? keychain.delete(matching: passwords()) }

        var item = Item(service: service, account: "one", password: "secret")
        item.isInvisible = true
        let reference = try keychain.add(item)

        let found = try #require(try keychain.fetchFirst(matching: passwords(account: "one")))
        #expect(found.password == "secret")
        #expect(found.isInvisible == true)
        #expect(found.synchronizable == false)
        #expect(found.accessGroup != nil)
        #expect(found.creationDate != nil)
        #expect(try keychain.fetchFirstPersistentReference(matching: passwords(account: "one")) == reference)

        var byReference = Query<GenericPassword>()
        byReference.persistentReference = reference
        #expect(try keychain.fetchFirst(matching: byReference)?.account == "one")
        // A keychain with a default access group must not send it along with the reference.
        #expect(try Keychain(accessGroup: found.accessGroup).fetchFirst(matching: byReference)?.account == "one")

        var changes = Item<GenericPassword>()
        changes.password = "changed"
        changes.comment = "rotated"
        try keychain.update(matching: passwords(account: "one"), with: changes)
        let updated = try #require(try keychain.fetchFirst(matching: passwords(account: "one")))
        #expect(updated.password == "changed")
        #expect(updated.comment == "rotated")

        try keychain.delete(matching: passwords(account: "one"))
        #expect(try keychain.fetchFirst(matching: passwords(account: "one")) == nil)
    }

    @Test func duplicateAddIsRejected() throws {
        defer { try? keychain.delete(matching: passwords()) }

        try keychain.add(Item(service: service, account: "one", password: "secret"))
        #expect(throws: KeychainError(code: .duplicateItem)) {
            try keychain.add(Item(service: service, account: "one", password: "again"))
        }
    }

    /// The data protection keychain acts on every match without a match limit, and rejects one.
    @Test func updateAndDeleteApplyToEveryMatch() throws {
        defer { try? keychain.delete(matching: passwords()) }

        try keychain.add(Item(service: service, account: "one", password: "1"))
        try keychain.add(Item(service: service, account: "two", password: "2"))
        #expect(Set(try keychain.fetch(matching: passwords()).compactMap(\.password)) == ["1", "2"])

        var changes = Item<GenericPassword>()
        changes.comment = "both"
        try keychain.update(matching: passwords(), with: changes)
        #expect(try keychain.fetchAttributes(matching: passwords()).map(\.comment) == ["both", "both"])

        try keychain.delete(matching: passwords())
        #expect(try keychain.fetchAttributes(matching: passwords()).isEmpty)
        #expect(throws: KeychainError(code: .itemNotFound)) {
            try keychain.update(matching: passwords(), with: changes)
        }
    }

    @Test func passwordThatWasReadCanBeChangedAndPassedBack() throws {
        defer { try? keychain.delete(matching: passwords()) }

        try keychain.add(Item(service: service, account: "one", password: "secret"))
        var item = try #require(try keychain.fetchFirst(matching: passwords(account: "one")))
        item.label = "renamed"
        try keychain.update(matching: passwords(account: "one"), with: item)
        #expect(try keychain.fetchFirstAttributes(matching: passwords(account: "one"))?.label == "renamed")
    }

    /// The keychain returns an access control object for every item, whichever form it was
    /// stored in, so the level is read from the object's `accessibility`.
    @Test(arguments: [
        Protection.accessible(.afterFirstUnlockThisDeviceOnly),
        nil,
        Protection.accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)),
    ])
    func protectionReadsBackAsAnAccessControlWithItsAccessibility(protection: Protection?) throws {
        defer { try? keychain.delete(matching: passwords()) }

        var item = Item(service: service, account: "one", password: "secret")
        item.attributes.protection = protection
        try keychain.add(item)
        let stored = try #require(try keychain.fetchFirstAttributes(matching: passwords(account: "one")))
        guard case .accessControl(let control)? = stored.protection else {
            Issue.record("expected an access control, got \(String(describing: stored.protection))")
            return
        }
        let expected: Accessibility? = switch protection {
        case .accessible(let accessibility)?: accessibility
        case .accessControl(let control)?: control.accessibility
        case nil: .whenUnlocked
        }
        #expect(control.accessibility == expected)
        #expect(stored.protection?.accessibility == expected)
        #expect(control.flags == nil)
    }

    /// The keychain rejects an access control with constraints next to an accessibility level.
    @Test func constrainedPasswordThatWasReadCanBeChangedAndPassedBack() throws {
        defer { try? keychain.delete(matching: passwords()) }

        var constrained = Item(service: service, account: "one", password: "secret")
        constrained.attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .userPresence))
        try keychain.add(constrained)
        var item = try #require(try keychain.fetchFirst(matching: passwords(account: "one")))
        item.label = "renamed"
        try keychain.update(matching: passwords(account: "one"), with: item)
        #expect(try keychain.fetchFirstAttributes(matching: passwords(account: "one"))?.label == "renamed")
    }

    @Test func asynchronousFormsReachTheKeychain() async throws {
        try await keychain.add(Item(service: service, account: "one", password: "secret"))
        #expect(try await keychain.fetchFirst(matching: passwords(account: "one"))?.password == "secret")
        #expect(try await keychain.fetch(matching: passwords()).count == 1)
        try await keychain.delete(matching: passwords())
        #expect(try await keychain.fetchFirst(matching: passwords()) == nil)
    }

    // MARK: Keys

    /// The data protection keychain returns the key class and type as numbers.
    @Test func addedKeyIsFoundWithItsAttributesAndReference() throws {
        defer { try? keychain.delete(matching: keys()) }

        let item = try keyItem(label: "one")
        try keychain.add(item)

        let found = try #require(try keychain.fetchFirst(matching: keys(label: "one")))
        #expect(found.keyClass == .private)
        #expect(found.keyType == .ecSECPrimeRandom)
        #expect(found.keySizeInBits == 256)
        #expect(found.canSign == true)
        #expect(found.applicationTag == tag)
        #expect(found.tokenID == nil)

        let stored = try #require(found.reference)
        let original = try #require(item.reference)
        #expect(try stored.externalRepresentation() == original.externalRepresentation())

        var privateKeys = keys()
        privateKeys.keyClass = .private
        var publicKeys = keys()
        publicKeys.keyClass = .public
        #expect(try keychain.fetchReferences(matching: privateKeys).count == 1)
        #expect(try keychain.fetchReferences(matching: publicKeys).isEmpty)
    }

    /// A key made from its external representation is accepted here, unlike in the file-based
    /// keychain.
    @Test func keyMadeFromDataCanBeAdded() throws {
        defer { try? keychain.delete(matching: keys()) }

        let generated = try KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256)
        let made = try KeyReference(
            externalRepresentation: generated.externalRepresentation(),
            keyType: .ecSECPrimeRandom,
            keyClass: .private,
        )
        var item = Item<CryptographicKey>(reference: made)
        item.applicationTag = tag
        try keychain.add(item)

        let stored = try #require(try keychain.fetchFirstReference(matching: keys()))
        #expect(try stored.externalRepresentation() == generated.externalRepresentation())
    }

    @Test func allReturnsEveryKeyInOneCall() throws {
        defer { try? keychain.delete(matching: keys()) }

        try keychain.add(keyItem(label: "one"))
        try keychain.add(keyItem(label: "two"))

        let items = try keychain.fetch(matching: keys())
        #expect(Set(items.map(\.label)) == ["one", "two"])
        #expect(items.allSatisfy { $0.reference != nil })
        #expect(try keychain.fetchReferences(matching: keys()).count == 2)
        #expect(try keychain.fetchPersistentReferences(matching: keys()).count == 2)

        try keychain.delete(matching: keys())
        #expect(try keychain.fetchAttributes(matching: keys()).isEmpty)
    }

    /// An item that was read carries its reference, which an update must leave out, and all of
    /// its attributes, which this keychain accepts back.
    @Test func keyThatWasReadCanBeChangedAndPassedBack() throws {
        defer { try? keychain.delete(matching: keys()) }

        try keychain.add(keyItem(label: "one"))
        var item = try #require(try keychain.fetchFirst(matching: keys()))
        #expect(item.reference != nil)
        item.label = "renamed"
        try keychain.update(matching: keys(), with: item)
        #expect(try keychain.fetchFirstAttributes(matching: keys())?.label == "renamed")
    }

    @Test func generatedKeyIsStoredAsThePrivateKeyAlone() throws {
        defer { try? keychain.delete(matching: keys()) }

        var attributes = Attributes<CryptographicKey>()
        attributes.applicationTag = tag
        attributes.label = "generated"
        let key = try keychain.generateKey(.ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)

        let stored = try keychain.fetch(matching: keys())
        #expect(stored.map(\.keyClass) == [.private])
        #expect(stored.first?.label == "generated")

        let found = try #require(stored.first?.reference)
        let signature = try found.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
        let publicKey = try #require(key.publicKey)
        #expect(try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))
    }

    /// The simulator emulates the Secure Enclave. It does not enforce the enclave's rules, so
    /// this shows the request is well formed and the token is recorded, not that the rules hold.
    @Test func secureEnclaveKeyIsStoredWithItsToken() throws {
        defer { try? keychain.delete(matching: keys()) }

        let key = try keychain.generateSecureEnclaveKey(applicationTag: tag, label: "enclave")

        let stored = try #require(try keychain.fetchFirst(matching: keys()))
        #expect(stored.tokenID == .secureEnclave)
        #expect(stored.keyClass == .private)
        #expect(stored.keySizeInBits == 256)

        let found = try #require(stored.reference)
        let signature = try found.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
        let publicKey = try #require(key.publicKey)
        #expect(try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))
        #expect(throws: KeychainError.self) {
            try found.externalRepresentation()
        }
    }

    /// A Secure Enclave key always holds an access control with `privateKeyUsage`, which the
    /// keychain rejects next to an accessibility level.
    @Test func secureEnclaveKeyThatWasReadCanBeChangedAndPassedBack() throws {
        defer { try? keychain.delete(matching: keys()) }

        _ = try keychain.generateSecureEnclaveKey(applicationTag: tag, label: "enclave")
        var item = try #require(try keychain.fetchFirst(matching: keys()))
        #expect(item.tokenID == .secureEnclave)
        item.label = "renamed"
        try keychain.update(matching: keys(), with: item)
        #expect(try keychain.fetchFirstAttributes(matching: keys())?.label == "renamed")
    }
}

/// Certificates and identities on the data protection keychain.
///
/// The fixture certificate has one primary key, so these tests share it and run one at a time,
/// each starting from a keychain without it.
@Suite(.serialized, .enabled(if: DataProtectionKeychain.isReachable, "The data protection keychain needs a host app."))
struct DataProtectionCertificateTests {
    private let keychain = Keychain()
    private let tag = Data("dev.sinoru.KeychainKit.tests.identity".utf8)
    private let message = Data("message".utf8)

    private var fixtureKeys: Query<CryptographicKey> {
        var query = Query<CryptographicKey>()
        query.applicationTag = tag
        return query
    }

    private func removeFixtures() {
        try? keychain.delete(matching: Query<Certificate>())
        try? keychain.delete(matching: fixtureKeys)
    }

    /// The data protection keychain reports the X.509 version as the certificate type.
    @Test func addedCertificateIsFoundWithItsAttributes() throws {
        removeFixtures()
        defer { removeFixtures() }

        try keychain.add(Item<Certificate>(reference: try ReferenceFixtures.makeCertificate()))

        var item = try #require(try keychain.fetchFirst(matching: Query<Certificate>()))
        #expect(item.reference?.derRepresentation == ReferenceFixtures.certificateData)
        #expect(item.certificateType == .x509v3)
        #expect(item.certificateEncoding == .der)
        #expect(item.subject != nil)
        #expect(item.issuer != nil)
        #expect(item.serialNumber != nil)

        var version3 = Query<Certificate>()
        version3.certificateType = .x509v3
        #expect(try keychain.fetchReferences(matching: version3).count == 1)

        item.label = "renamed"
        try keychain.update(matching: Query<Certificate>(), with: item)
        #expect(try keychain.fetchFirstAttributes(matching: Query<Certificate>())?.label == "renamed")
    }

    /// An identity here carries the attributes of both its certificate and its private key.
    @Test func certificateAndItsPrivateKeyFormAnIdentity() throws {
        removeFixtures()
        defer { removeFixtures() }

        #expect(try keychain.fetchFirstReference(matching: Query<Identity>()) == nil)

        let key = try KeyReference(
            externalRepresentation: ReferenceFixtures.privateKeyData,
            keyType: .ecSECPrimeRandom,
            keyClass: .private,
        )
        var keyItem = Item<CryptographicKey>(reference: key)
        keyItem.applicationTag = tag
        try keychain.add(keyItem)
        try keychain.add(Item<Certificate>(reference: try ReferenceFixtures.makeCertificate()))

        let identity = try #require(try keychain.fetchFirst(matching: Query<Identity>()))
        #expect(identity.subject != nil)
        #expect(identity.keyClass == .private)
        #expect(identity.applicationTag == tag)
        #expect(try keychain.fetchReferences(matching: Query<Identity>()).count == 1)

        let reference = try #require(identity.reference)
        #expect(try reference.certificate().derRepresentation == ReferenceFixtures.certificateData)

        let privateKey = try reference.privateKey()
        let publicKey = try #require(try reference.certificate().publicKey)
        let signature = try privateKey.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
        #expect(try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))
    }
}
#endif
