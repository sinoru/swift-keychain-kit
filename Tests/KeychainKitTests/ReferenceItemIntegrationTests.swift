//
//  ReferenceItemIntegrationTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
import Foundation
import Security
import Testing

import KeychainKit

/// Stores keys, certificates, and identities in a temporary file-based keychain through the
/// public `Keychain` API.
@Suite struct ReferenceItemIntegrationTests {
    private func withKeychain(_ body: (Keychain) throws -> Void) throws {
        try withFileKeychain { try body(Keychain(storage: .fileBased($0))) }
    }

    private func withFileKeychain(_ body: (FileKeychain) throws -> Void) throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        try body(temporary.fileKeychain)
    }

    private static let tag = Data("dev.sinoru.KeychainKit.tests".utf8)

    private func keyItem(label: String) throws -> Item<CryptographicKey> {
        var item = Item<CryptographicKey>(reference: try ReferenceFixtures.makeKey())
        item.label = label
        item.applicationTag = Self.tag
        return item
    }

    private func keys(label: String? = nil) -> Query<CryptographicKey> {
        var query = Query<CryptographicKey>()
        query.applicationTag = Self.tag
        query.label = label
        return query
    }

    private func publicKeyData(of key: KeyReference) throws -> Data {
        let publicKey = try #require(SecKeyCopyPublicKey(key.reference))
        let data = SecKeyCopyExternalRepresentation(publicKey, nil)
        return try #require(data) as Data
    }

    // MARK: Keys

    @Test func addedKeyIsFoundWithItsAttributesAndReference() throws {
        try withKeychain { keychain in
            let reference = try keychain.add(keyItem(label: "one"))
            #expect(!reference.rawValue.isEmpty)

            let found = try #require(try keychain.fetchFirst(matching: keys(label: "one")))
            #expect(found.reference != nil)
            #expect(found.label == "one")
            #expect(found.applicationTag == Self.tag)
            #expect(found.keyClass == .private)
            #expect(found.keyType == .ecSECPrimeRandom)
            #expect(found.keySizeInBits == 256)
            #expect(found.canSign == true)
        }
    }

    @Test func referenceOfAStoredKeyIsUsable() throws {
        try withKeychain { keychain in
            let item = try keyItem(label: "one")
            try keychain.add(item)
            let stored = try #require(try keychain.fetchFirstReference(matching: keys()))

            let original = try #require(item.reference)
            #expect(try publicKeyData(of: stored) == publicKeyData(of: original))
        }
    }

    @Test func allReturnsEveryKey() throws {
        try withKeychain { keychain in
            try keychain.add(keyItem(label: "one"))
            try keychain.add(keyItem(label: "two"))

            let items = try keychain.fetch(matching: keys())
            #expect(Set(items.map(\.label)) == ["one", "two"])
            #expect(items.allSatisfy { $0.reference != nil })
            #expect(try keychain.fetchReferences(matching: keys()).count == 2)
            #expect(try keychain.fetchAttributes(matching: keys()).count == 2)
            #expect(try keychain.fetchPersistentReferences(matching: keys()).count == 2)
        }
    }

    @Test func nothingMatchingIsNotAnError() throws {
        try withKeychain { (keychain: Keychain) throws in
            #expect(try keychain.fetchFirst(matching: keys()) == nil)
            #expect(try keychain.fetchFirstReference(matching: keys()) == nil)
            #expect(try keychain.fetch(matching: keys()).isEmpty)
            #expect(try keychain.fetchReferences(matching: keys()).isEmpty)
        }
    }

    @Test func updateAndDeleteApplyToKeys() throws {
        try withKeychain { keychain in
            try keychain.add(keyItem(label: "one"))
            try keychain.add(keyItem(label: "two"))

            var changes = Item<CryptographicKey>()
            changes.label = "renamed"
            try keychain.update(matching: keys(label: "one"), with: changes)
            #expect(try keychain.fetchFirstAttributes(matching: keys(label: "renamed")) != nil)

            try keychain.delete(matching: keys())
            #expect(try keychain.fetchReferences(matching: keys()).isEmpty)
        }
    }

    @Test func asynchronousFormsReturnTheSameResults() async throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        try await keychain.add(keyItem(label: "one"))
        #expect(try await keychain.fetchFirst(matching: keys())?.label == "one")
        #expect(try await keychain.fetchFirstReference(matching: keys()) != nil)
        #expect(try await keychain.fetch(matching: keys()).count == 1)
        #expect(try await keychain.fetchReferences(matching: keys()).count == 1)
    }

    // MARK: Generation

    @Test func generatedKeyIsStoredAsThePrivateKeyAlone() throws {
        try withKeychain { keychain in
            var attributes = Attributes<CryptographicKey>()
            attributes.applicationTag = Self.tag
            attributes.label = "generated"
            let key = try keychain.generateKey(.ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)

            let stored = try keychain.fetch(matching: Query<CryptographicKey>())
            #expect(stored.count == 1)
            #expect(stored.first?.keyClass == .private)
            #expect(stored.first?.label == "generated")
            #expect(stored.first?.applicationTag == Self.tag)

            let found = try #require(try keychain.fetchFirstReference(matching: keys(label: "generated")))
            let message = Data("message".utf8)
            let signature = try found.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
            let publicKey = try #require(key.publicKey)
            #expect(try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))
        }
    }

    @Test func asynchronousGenerationStoresTheKey() async throws {
        let temporary = try TemporaryFileKeychain()
        defer { try? temporary.tearDown() }
        let keychain = Keychain(storage: .fileBased(temporary.fileKeychain))

        var attributes = Attributes<CryptographicKey>()
        attributes.applicationTag = Self.tag
        _ = try await keychain.generateKey(.rsa, sizeInBits: 2048, attributes: attributes)
        #expect(try await keychain.fetchFirst(matching: keys())?.keyType == .rsa)
    }

    // MARK: Certificates and identities

    @Test func addedCertificateIsFoundWithItsAttributes() throws {
        try withKeychain { keychain in
            let certificate = try ReferenceFixtures.makeCertificate()
            try keychain.add(Item<Certificate>(reference: certificate))

            let found = try #require(try keychain.fetchFirst(matching: Query<Certificate>()))
            let reference = try #require(found.reference)
            #expect(reference.derRepresentation == ReferenceFixtures.certificateData)
            #expect(found.subject != nil)
            #expect(found.issuer != nil)
            #expect(found.serialNumber != nil)
            // The file-based keychain does not report the version here; see `CertificateType`.
            #expect(found.certificateType != nil)
            #expect(found.certificateEncoding == .der)
            #expect(try keychain.fetchReferences(matching: Query<Certificate>()).count == 1)
        }
    }

    @Test func certificateThatWasReadCanBeChangedAndPassedBack() throws {
        try withKeychain { keychain in
            try keychain.add(Item<Certificate>(reference: try ReferenceFixtures.makeCertificate()))

            var item = try #require(try keychain.fetchFirst(matching: Query<Certificate>()))
            #expect(item.reference != nil)
            item.label = "renamed"
            try keychain.update(matching: Query<Certificate>(), with: item)
            #expect(try keychain.fetchFirstAttributes(matching: Query<Certificate>())?.label == "renamed")
        }
    }

    /// The file-based keychain rejects a key's own attributes in an update, so only the change
    /// is passed; the reference on it is left out by the library.
    @Test func keyIsUpdatedWithOnlyTheChange() throws {
        try withKeychain { keychain in
            try keychain.add(keyItem(label: "one"))
            let read = try #require(try keychain.fetchFirst(matching: keys()))

            var changes = Item<CryptographicKey>(reference: read.reference)
            changes.label = "renamed"
            try keychain.update(matching: keys(), with: changes)
            #expect(try keychain.fetchFirstAttributes(matching: keys())?.label == "renamed")

            var whole = read
            whole.label = "again"
            #expect(throws: KeychainError.self) {
                try keychain.update(matching: keys(), with: whole)
            }
        }
    }

    /// The private key goes in through `SecItemImport` because the file-based keychain rejects
    /// an add of a key made by `SecKeyCreateWithData` with `errSecParam`; it accepts only keys
    /// it generated (measured on macOS 26).
    @Test func certificateAndItsPrivateKeyFormAnIdentity() throws {
        try withFileKeychain { fileKeychain in
            let keychain = Keychain(storage: .fileBased(fileKeychain))
            #expect(try keychain.fetchFirstReference(matching: Query<Identity>()) == nil)

            let status = SecItemImport(
                Data(ReferenceFixtures.privateKeyPEM.utf8) as CFData, nil, nil, nil, [], nil, fileKeychain.reference, nil,
            )
            try #require(status == errSecSuccess)
            try keychain.add(Item<Certificate>(reference: try ReferenceFixtures.makeCertificate()))

            let identity = try #require(try keychain.fetchFirst(matching: Query<Identity>()))
            #expect(identity.subject != nil)

            let reference = try #require(identity.reference)
            #expect(try reference.certificate().derRepresentation == ReferenceFixtures.certificateData)

            // The private key is the certified one: its signature verifies under the public key
            // taken from the certificate.
            let privateKey = try reference.privateKey()
            let publicKey = try #require(try reference.certificate().publicKey)
            let message = Data("message".utf8)
            let signature = try privateKey.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
            #expect(try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))
            #expect(try #require(privateKey.publicKey).externalRepresentation() == ReferenceFixtures.publicKeyData)
            #expect(try keychain.fetchReferences(matching: Query<Identity>()).count == 1)
        }
    }
}
#endif
