//
//  KeyReferenceOperationsTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

/// Runs the `SecKey` operations on keys that are never stored, so no keychain is involved.
@Suite struct KeyReferenceOperationsTests {
    private let message = Data("message".utf8)

    private func ellipticCurveKey() throws -> KeyReference {
        try KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256)
    }

    // MARK: Creating and exporting

    @Test func generatedKeyIsAPrivateKeyOfTheRequestedTypeAndSize() throws {
        let key = try KeyReference(generating: .rsa, sizeInBits: 2048)
        let copied = try #require(SecKeyCopyAttributes(key.reference))
        let attributes = Attributes<CryptographicKey>(secDictionary: try #require(SecDictionary(cf: copied)))
        #expect(attributes.keyClass == .private)
        #expect(attributes.keyType == .rsa)
        #expect(attributes.keySizeInBits == 2048)
        // `kSecAttrIsPermanent` is not checked: `SecKeyCopyAttributes` reports it as false for
        // this key on macOS and as true on the other platforms, where the framework marks every
        // software key permanent whether or not it is stored (measured in CI on the iOS, tvOS,
        // watchOS, and visionOS simulators and Mac Catalyst).
    }

    @Test func generationReportsAnUnsupportedSize() {
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 123)
        }
    }

    @Test func externalRepresentationRoundTrips() throws {
        let key = try ellipticCurveKey()
        let publicKey = try #require(key.publicKey)

        let privateData = try key.externalRepresentation()
        let publicData = try publicKey.externalRepresentation()
        // ANSI X9.63: 04 || X || Y for the public key, with K appended for the private key.
        #expect(publicData.count == 65)
        #expect(privateData.count == 97)
        #expect(privateData.prefix(65) == publicData)

        let restored = try KeyReference(externalRepresentation: privateData, keyType: .ecSECPrimeRandom, keyClass: .private)
        #expect(try restored.externalRepresentation() == privateData)
        #expect(try #require(restored.publicKey).externalRepresentation() == publicData)
    }

    @Test func malformedExternalRepresentationIsRejected() {
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try KeyReference(externalRepresentation: Data([1, 2, 3]), keyType: .ecSECPrimeRandom, keyClass: .public)
        }
    }

    @Test func publicKeyOfAPublicKeyIsThatKey() throws {
        let publicKey = try #require(try ellipticCurveKey().publicKey)
        #expect(try #require(publicKey.publicKey).externalRepresentation() == publicKey.externalRepresentation())
    }

    // MARK: Algorithms

    @Test func algorithmsCarryTheFrameworkConstants() {
        #expect(KeyAlgorithm.ecdsaSignatureMessageX962SHA256.rawValue == SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256.rawValue as String)
        #expect(KeyAlgorithm.rsaEncryptionOAEPSHA256.rawValue == SecKeyAlgorithm.rsaEncryptionOAEPSHA256.rawValue as String)
        #expect(KeyAlgorithm.ecdhKeyExchangeStandard.rawValue == SecKeyAlgorithm.ecdhKeyExchangeStandard.rawValue as String)
    }

    @Test func supportDependsOnTheKeyAndTheOperation() throws {
        let key = try ellipticCurveKey()
        let publicKey = try #require(key.publicKey)
        #expect(key.supports(.ecdsaSignatureMessageX962SHA256, for: .sign))
        #expect(!key.supports(.rsaSignatureMessagePKCS1v15SHA256, for: .sign))
        #expect(!publicKey.supports(.ecdsaSignatureMessageX962SHA256, for: .sign))
        #expect(publicKey.supports(.ecdsaSignatureMessageX962SHA256, for: .verify))
        #expect(key.supports(.ecdhKeyExchangeStandard, for: .keyExchange))
    }

    // MARK: Signing

    @Test func signatureVerifiesOnlyAgainstTheSignedData() throws {
        let key = try ellipticCurveKey()
        let publicKey = try #require(key.publicKey)
        let signature = try key.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)

        #expect(try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))
        #expect(try !publicKey.isValidSignature(signature, for: Data("other".utf8), using: .ecdsaSignatureMessageX962SHA256))
        #expect(try !publicKey.isValidSignature(Data([1, 2, 3]), for: message, using: .ecdsaSignatureMessageX962SHA256))
    }

    @Test func anOperationTheKeyCannotPerformIsThrown() throws {
        let key = try ellipticCurveKey()
        let publicKey = try #require(key.publicKey)
        let signature = try key.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)

        #expect(throws: KeychainError(code: .invalidParameter)) {
            try key.signature(for: message, using: .rsaSignatureMessagePKCS1v15SHA256)
        }
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try publicKey.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
        }
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try publicKey.isValidSignature(signature, for: message, using: .rsaSignatureMessagePKCS1v15SHA256)
        }
    }

    // MARK: Encryption

    @Test(arguments: [
        (KeyType.rsa, 2048, KeyAlgorithm.rsaEncryptionOAEPSHA256),
        (KeyType.ecSECPrimeRandom, 256, KeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM),
    ])
    func encryptedDataDecryptsWithThePrivateKey(keyType: KeyType, size: Int, algorithm: KeyAlgorithm) throws {
        let key = try KeyReference(generating: keyType, sizeInBits: size)
        let publicKey = try #require(key.publicKey)

        let ciphertext = try publicKey.encryptedData(for: message, using: algorithm)
        #expect(ciphertext != message)
        #expect(try key.decryptedData(for: ciphertext, using: algorithm) == message)
    }

    @Test func malformedCiphertextIsRejected() throws {
        let key = try KeyReference(generating: .rsa, sizeInBits: 2048)
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try key.decryptedData(for: Data(repeating: 1, count: 256), using: .rsaEncryptionOAEPSHA256)
        }
    }

    // MARK: Key exchange

    @Test func bothPartiesDeriveTheSameSecret() throws {
        let ours = try ellipticCurveKey()
        let theirs = try ellipticCurveKey()

        let secret = try ours.keyExchangeResult(with: try #require(theirs.publicKey), using: .ecdhKeyExchangeStandard)
        #expect(secret.count == 32)
        #expect(try theirs.keyExchangeResult(with: try #require(ours.publicKey), using: .ecdhKeyExchangeStandard) == secret)
    }

    @Test func keyDerivationProducesTheRequestedSize() throws {
        let ours = try ellipticCurveKey()
        let theirPublicKey = try #require(try ellipticCurveKey().publicKey)

        let derived = try ours.keyExchangeResult(
            with: theirPublicKey,
            using: .ecdhKeyExchangeStandardX963SHA256,
            requestedSize: 48,
            sharedInfo: Data([1]),
        )
        #expect(derived.count == 48)
        #expect(throws: KeychainError(code: .invalidParameter)) {
            try ours.keyExchangeResult(with: theirPublicKey, using: .ecdhKeyExchangeStandardX963SHA256)
        }
    }

    // MARK: Asynchronous forms

    @Test func asynchronousFormsReturnTheSameResults() async throws {
        let key = try await KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256)
        let publicKey = try #require(key.publicKey)
        #expect(try await key.externalRepresentation().count == 97)

        let signature = try await key.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
        #expect(try await publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256))

        let algorithm = KeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        let ciphertext = try await publicKey.encryptedData(for: message, using: algorithm)
        #expect(try await key.decryptedData(for: ciphertext, using: algorithm) == message)

        let other = try await KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256)
        let secret = try await key.keyExchangeResult(with: try #require(other.publicKey), using: .ecdhKeyExchangeStandard)
        #expect(try await other.keyExchangeResult(with: publicKey, using: .ecdhKeyExchangeStandard) == secret)
    }

    @Test func asynchronousFormsThrowTheSameErrors() async throws {
        let key = try await KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256)
        await #expect(throws: KeychainError(code: .invalidParameter)) {
            try await key.signature(for: Data(), using: .rsaSignatureMessagePKCS1v15SHA256)
        }
        await #expect(throws: KeychainError(code: .invalidParameter)) {
            try await KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 123)
        }
    }

    // MARK: Generation into a keychain

    @Test func generationPutsTheStoredKeyAttributesUnderThePrivateKey() throws {
        var attributes = Attributes<CryptographicKey>()
        attributes.applicationTag = Data([1])
        attributes.label = "label"
        attributes.tokenID = .secureEnclave
        attributes.keyType = .rsa

        let keychain = Keychain(accessGroup: AccessGroup(rawValue: "TEAM.group"))
        let dictionary = keychain.generationDictionary(for: .ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)
        #expect(dictionary == [
            SecItemKey(kSecAttrKeyType): .string(kSecAttrKeyTypeECSECPrimeRandom as String),
            SecItemKey(kSecAttrKeySizeInBits): .integer(256),
            SecItemKey(kSecAttrTokenID): .string(kSecAttrTokenIDSecureEnclave as String),
            SecItemKey(kSecUseDataProtectionKeychain): .bool(true),
            SecItemKey(kSecPrivateKeyAttrs): .dictionary([
                SecItemKey(kSecAttrIsPermanent): .bool(true),
                SecItemKey(kSecAttrApplicationTag): .data(Data([1])),
                SecItemKey(kSecAttrLabel): .string("label"),
                SecItemKey(kSecAttrAccessGroup): .string("TEAM.group"),
            ]),
        ])
    }

    /// Only the request can be checked here: the Secure Enclave is out of reach for an unsigned
    /// test runner.
    @Test func secureEnclaveKeyIsAlwaysAP256KeyWithPrivateKeyUsage() throws {
        let attributes = try Keychain.secureEnclaveKeyAttributes(
            applicationTag: Data([1]),
            label: "label",
            accessGroup: nil,
            accessibility: .whenUnlockedThisDeviceOnly,
            constraints: .biometryAny,
        )
        #expect(attributes.tokenID == .secureEnclave)
        #expect(attributes.applicationTag == Data([1]))
        #expect(attributes.label == "label")
        let expected = try AccessControl(accessibility: .whenUnlockedThisDeviceOnly, flags: [.privateKeyUsage, .biometryAny])
        #expect(attributes.protection == .accessControl(expected))

        let unconstrained = try Keychain.secureEnclaveKeyAttributes(
            applicationTag: nil, label: nil, accessGroup: nil, accessibility: .afterFirstUnlockThisDeviceOnly, constraints: [],
        )
        let minimum = try AccessControl(accessibility: .afterFirstUnlockThisDeviceOnly, flags: .privateKeyUsage)
        #expect(unconstrained.protection == .accessControl(minimum))

        let dictionary = Keychain().generationDictionary(for: .ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)
        #expect(dictionary[SecItemKey(kSecAttrTokenID)] == .string(kSecAttrTokenIDSecureEnclave as String))
        guard case .dictionary(let privateKey)? = dictionary[SecItemKey(kSecPrivateKeyAttrs)] else {
            Issue.record("no private key attributes")
            return
        }
        #expect(privateKey[SecItemKey(kSecAttrTokenID)] == nil)
        #expect(privateKey[SecItemKey(kSecAttrIsPermanent)] == .bool(true))
        #expect(privateKey[SecItemKey(kSecAttrAccessControl)] != nil)
    }
}
