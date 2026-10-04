//
//  ReferenceItemTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security
import Testing

@testable import KeychainKit

/// Checks the reference wrappers and what the key, certificate, and identity classes send to
/// and read from the framework, without a keychain.
@Suite struct ReferenceItemTests {
    // MARK: References

    @Test func referenceWrapsOnlyAnObjectOfItsOwnType() throws {
        let key = try ReferenceFixtures.makeKey()
        let certificate = try ReferenceFixtures.makeCertificate()

        #expect(KeyReference(key.reference as AnyObject) == key)
        #expect(CertificateReference(certificate.reference as AnyObject) == certificate)

        #expect(KeyReference(certificate.reference as AnyObject) == nil)
        #expect(CertificateReference(key.reference as AnyObject) == nil)
        #expect(IdentityReference(key.reference as AnyObject) == nil)
        #expect(KeyReference("string" as CFString) == nil)
    }

#if os(macOS)
    /// A proxy answers what it is asked by forwarding it, and one that will not forward a message
    /// raises instead. Core Foundation asks an object that is not its own for a type ID with a
    /// message, so a proxy has to be turned away before that question rather than by it. Anything
    /// short of that does not fail this test; it ends the process. `NSProtocolChecker` is in the
    /// macOS SDK only.
    @Test func referenceTurnsAwayAProxyWithoutSendingItAMessage() {
        let proxy = NSProtocolChecker(target: NSObject(), protocol: (any NSObjectProtocol).self)

        #expect(KeyReference(proxy) == nil)
        #expect(CertificateReference(proxy) == nil)
        #expect(IdentityReference(proxy) == nil)
    }
#endif

    /// The reason the wrappers check the type ID: a cast to a Core Foundation type succeeds for
    /// an object of any other Core Foundation type.
    @Test func castToACoreFoundationTypeDoesNotDiscriminate() throws {
        func cast<T: AnyObject>(_ object: AnyObject, to type: T.Type) -> T? {
            object as? T
        }
        let certificate = try ReferenceFixtures.makeCertificate()
        #expect(cast(certificate.reference, to: SecKey.self) != nil)
        #expect(CFGetTypeID(certificate.reference) != SecKeyGetTypeID())
    }

    @Test func referencesCompareByIdentity() throws {
        let key = try ReferenceFixtures.makeKey()
        #expect(key == KeyReference(reference: key.reference))
        #expect(key.hashValue == KeyReference(reference: key.reference).hashValue)
        #expect(key != (try ReferenceFixtures.makeKey()))
    }

    @Test func certificateRoundTripsThroughItsDEREncoding() throws {
        let certificate = try #require(CertificateReference(derRepresentation: ReferenceFixtures.certificateData))
        #expect(certificate.derRepresentation == ReferenceFixtures.certificateData)
        #expect(CertificateReference(derRepresentation: Data([1, 2, 3])) == nil)
        #expect(CertificateReference(derRepresentation: Data()) == nil)
    }

    @Test func certificateYieldsThePublicKeyItCertifies() throws {
        let publicKey = try #require(try ReferenceFixtures.makeCertificate().publicKey)
        #expect(try publicKey.externalRepresentation() == ReferenceFixtures.publicKeyData)
        #expect(publicKey.supports(.ecdsaSignatureMessageX962SHA256, for: .verify))
    }

    // MARK: Attributes

    @Test func keyPropertiesStoreUnderTheirSecurityKeys() {
        var attributes = Attributes<CryptographicKey>()
        attributes.label = "label"
        attributes.keyType = .ecSECPrimeRandom
        attributes.keySizeInBits = 256
        attributes.effectiveKeySize = 256
        attributes.applicationLabel = Data([1])
        attributes.applicationTag = Data([2])
        attributes.isPermanent = true
        attributes.canEncrypt = false
        attributes.canDecrypt = true
        attributes.canDerive = true
        attributes.canSign = true
        attributes.canVerify = false
        attributes.canWrap = false
        attributes.canUnwrap = true
        attributes.tokenID = .secureEnclave
        #expect(attributes.storage == [
            SecItemKey(kSecAttrLabel): .string("label"),
            SecItemKey(kSecAttrKeyType): .string(kSecAttrKeyTypeECSECPrimeRandom as String),
            SecItemKey(kSecAttrKeySizeInBits): .integer(256),
            SecItemKey(kSecAttrEffectiveKeySize): .integer(256),
            SecItemKey(kSecAttrApplicationLabel): .data(Data([1])),
            SecItemKey(kSecAttrApplicationTag): .data(Data([2])),
            SecItemKey(kSecAttrIsPermanent): .bool(true),
            SecItemKey(kSecAttrCanEncrypt): .bool(false),
            SecItemKey(kSecAttrCanDecrypt): .bool(true),
            SecItemKey(kSecAttrCanDerive): .bool(true),
            SecItemKey(kSecAttrCanSign): .bool(true),
            SecItemKey(kSecAttrCanVerify): .bool(false),
            SecItemKey(kSecAttrCanWrap): .bool(false),
            SecItemKey(kSecAttrCanUnwrap): .bool(true),
            SecItemKey(kSecAttrTokenID): .string(kSecAttrTokenIDSecureEnclave as String),
        ])
        #expect(attributes.keyType == .ecSECPrimeRandom)
        #expect(attributes.keySizeInBits == 256)
        #expect(attributes.applicationTag == Data([2]))
        #expect(attributes.canSign == true)
        #expect(attributes.tokenID == .secureEnclave)
        #expect(attributes.keyClass == nil)
    }

    /// `SecKeyCopyAttributes` reports the class and type as the string constants, while the
    /// header documents numbers; a property reads either.
    @Test func keyClassAndTypeReadFromEitherForm() throws {
        let key = try ReferenceFixtures.makeKey()
        let copied = try #require(SecKeyCopyAttributes(key.reference))
        let fromFramework = Attributes<CryptographicKey>(secDictionary: try #require(SecDictionary(cf: copied)))
        #expect(fromFramework.keyClass == .private)
        #expect(fromFramework.keyType == .ecSECPrimeRandom)
        #expect(fromFramework.keySizeInBits == 256)
        #expect(fromFramework.canSign == true)

        let numeric = Attributes<CryptographicKey>(secDictionary: [
            SecItemKey(kSecAttrKeyClass): .integer(0),
            SecItemKey(kSecAttrKeyType): .integer(42),
        ])
        #expect(numeric.keyClass == .public)
        #expect(numeric.keyType == .rsa)
    }

    @Test func certificatePropertiesReadTheirSecurityKeys() {
        let attributes = Attributes<Certificate>(secDictionary: [
            SecItemKey(kSecAttrCertificateType): .integer(3),
            SecItemKey(kSecAttrCertificateEncoding): .integer(3),
            SecItemKey(kSecAttrSubject): .data(Data([1])),
            SecItemKey(kSecAttrIssuer): .data(Data([2])),
            SecItemKey(kSecAttrSerialNumber): .data(Data([3])),
            SecItemKey(kSecAttrSubjectKeyID): .data(Data([4])),
            SecItemKey(kSecAttrPublicKeyHash): .data(Data([5])),
        ])
        #expect(attributes.certificateType == .x509v3)
        #expect(attributes.certificateEncoding == .der)
        #expect(attributes.subject == Data([1]))
        #expect(attributes.issuer == Data([2]))
        #expect(attributes.serialNumber == Data([3]))
        #expect(attributes.subjectKeyID == Data([4]))
        #expect(attributes.publicKeyHash == Data([5]))
    }

    @Test func identityCarriesTheAttributesOfBothHalves() {
        let item = Item<Identity>(attributes: Attributes(secDictionary: [
            SecItemKey(kSecAttrKeyClass): .string(kSecAttrKeyClassPrivate as String),
            SecItemKey(kSecAttrSubject): .data(Data([1])),
        ]))
        #expect(item.keyClass == .private)
        #expect(item.subject == Data([1]))
    }

    @Test func itemAndQueryForwardToAttributes() {
        var item = Item<CryptographicKey>()
        item.applicationTag = Data([1])
        item.canSign = true
        #expect(item.attributes.applicationTag == Data([1]))
        #expect(item.attributes.canSign == true)

        var keys = Query<CryptographicKey>()
        keys.applicationTag = Data([1])
        keys.keyClass = .private
        #expect(keys.attributes.storage == [
            SecItemKey(kSecAttrApplicationTag): .data(Data([1])),
            SecItemKey(kSecAttrKeyClass): .string(kSecAttrKeyClassPrivate as String),
        ])

        var certificates = Query<Certificate>()
        certificates.certificateType = .x509v3
        certificates.subject = Data([2])
        certificates.subject = nil
        #expect(certificates.attributes.storage == [SecItemKey(kSecAttrCertificateType): .integer(3)])
    }

    // MARK: Requests

    @Test func addSendsTheReferenceInsteadOfData() throws {
        let key = try ReferenceFixtures.makeKey()
        var item = Item<CryptographicKey>(reference: key)
        item.applicationTag = Data([1])
        #expect(item.reference == key)

        let dictionary = Keychain().addDictionary(for: item)
        #expect(dictionary[SecItemKey(kSecClass)] == .string(kSecClassKey as String))
        #expect(dictionary[SecItemKey(kSecValueRef)] == .object(SecObject(key.reference)))
        #expect(dictionary[SecItemKey(kSecValueData)] == nil)
        #expect(dictionary[SecItemKey(kSecAttrApplicationTag)] == .data(Data([1])))
        #expect(dictionary[SecItemKey(kSecReturnPersistentRef)] == .bool(true))

        #expect(Keychain().addDictionary(for: Item<CryptographicKey>())[SecItemKey(kSecValueRef)] == nil)
    }

    /// An item that was read carries its reference, and the data protection keychain rejects a
    /// reference among the attributes to update.
    @Test func updateLeavesTheReferenceOut() throws {
        var changes = Item<CryptographicKey>(reference: try ReferenceFixtures.makeKey())
        changes.label = "renamed"
        #expect(Keychain.updateDictionary(for: changes) == [SecItemKey(kSecAttrLabel): .string("renamed")])
    }

    @Test func searchAsksForAReference() {
        let dictionary = Keychain().requestDictionary(for: Query<Certificate>(), returning: [.attributes, .reference], all: true)
        #expect(dictionary[SecItemKey(kSecClass)] == .string(kSecClassCertificate as String))
        #expect(dictionary[SecItemKey(kSecReturnRef)] == .bool(true))
        #expect(dictionary[SecItemKey(kSecReturnAttributes)] == .bool(true))
        #expect(dictionary[SecItemKey(kSecReturnData)] == nil)
        #expect(dictionary[SecItemKey(kSecMatchLimit)] == .string(kSecMatchLimitAll as String))
    }

    // MARK: Results

    @Test func itemSeparatesTheReferenceFromAttributes() throws {
        let key = try ReferenceFixtures.makeKey()
        let item: Item<CryptographicKey> = try Keychain.item(from: .dictionary([
            SecItemKey(kSecClass): .string(kSecClassKey as String),
            SecItemKey(kSecAttrApplicationTag): .data(Data([1])),
            SecItemKey(kSecValueRef): .object(SecObject(key.reference)),
        ]))
        #expect(item.reference == key)
        #expect(item.applicationTag == Data([1]))
        #expect(item.attributes.storage[SecItemKey(kSecValueRef)] == nil)
    }

    @Test func referenceOfAnotherTypeIsADecodingFailure() throws {
        let key = try ReferenceFixtures.makeKey()
        let value = SecValue.object(SecObject(key.reference))
        #expect(try Keychain.reference(from: value) as KeyReference == key)
        #expect(throws: KeychainError(code: .decodingFailed)) {
            try Keychain.reference(from: value) as CertificateReference
        }
        #expect(throws: KeychainError(code: .decodingFailed)) {
            try Keychain.reference(from: .data(Data())) as KeyReference
        }

        let mistyped: Item<Certificate> = try Keychain.item(from: .dictionary([SecItemKey(kSecValueRef): value]))
        #expect(mistyped.reference == nil)
    }
}
