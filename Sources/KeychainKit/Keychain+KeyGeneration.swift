//
//  Keychain+KeyGeneration.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Keychain {
    /// Generates a private key and stores it in the keychain (`SecKeyCreateRandomKey`).
    ///
    /// `attributes` describe the stored private key: give it an `applicationTag` or a `label` to
    /// find it by later, and a `protection` to restrict its use. The public key is not stored;
    /// take it from `KeyReference/publicKey` when needed. A key whose access control requires an
    /// application password needs `authenticationContext`, as an item passed to `add` does.
    public func generateKey(
        _ keyType: KeyType,
        sizeInBits: Int,
        attributes: Attributes<CryptographicKey> = Attributes(),
        authenticationContext: AuthenticationContext? = nil,
    ) throws(KeychainError) -> KeyReference {
        let parameters = generationDictionary(
            for: keyType,
            sizeInBits: sizeInBits,
            attributes: attributes,
            authenticationContext: authenticationContext,
        )
        try storage.validate(parameters)
        return try KeyReference(generatingWith: parameters)
    }

    /// Generates a private key inside the Secure Enclave and stores it in the keychain.
    ///
    /// The key never leaves the Secure Enclave: it cannot be exported, and only the device that
    /// made it can use it. The Secure Enclave works only with 256-bit NIST P curve keys, which
    /// sign and take part in elliptic curve Diffie-Hellman key exchange, and by extension ECIES
    /// encryption, so the type and size are not parameters. Neither is the `privateKeyUsage`
    /// flag, without which generation succeeds but signing fails: it is always part of the access
    /// control, and `constraints` adds to it, for example `biometryAny` to require the user.
    ///
    /// Fails on a device without a Secure Enclave. The simulator emulates one without enforcing
    /// these rules, so it is no evidence that a combination works on hardware (measured on the
    /// iOS 27 simulator, which accepted a 384-bit key and a key without access control).
    ///
    /// `authenticationContext` supplies the application password when `constraints` asks for
    /// one, and the prompt settings for a key the user must authenticate to use.
    public func generateSecureEnclaveKey(
        applicationTag: Data? = nil,
        label: String? = nil,
        accessGroup: AccessGroup? = nil,
        accessibility: Accessibility = .whenUnlockedThisDeviceOnly,
        constraints: AccessControl.Flags = [],
        authenticationContext: AuthenticationContext? = nil,
    ) throws(KeychainError) -> KeyReference {
        let attributes = try Self.secureEnclaveKeyAttributes(
            applicationTag: applicationTag,
            label: label,
            accessGroup: accessGroup,
            accessibility: accessibility,
            constraints: constraints,
        )
        return try generateKey(.ecSECPrimeRandom, sizeInBits: 256, attributes: attributes, authenticationContext: authenticationContext)
    }

    /// The attributes of a Secure Enclave key: the token, and an access control that always
    /// carries `privateKeyUsage`.
    package static func secureEnclaveKeyAttributes(
        applicationTag: Data?,
        label: String?,
        accessGroup: AccessGroup?,
        accessibility: Accessibility,
        constraints: AccessControl.Flags,
    ) throws(KeychainError) -> Attributes<CryptographicKey> {
        var attributes = Attributes<CryptographicKey>()
        attributes.applicationTag = applicationTag
        attributes.label = label
        attributes.accessGroup = accessGroup
        attributes.tokenID = .secureEnclave
        attributes.protection = .accessControl(
            try AccessControl(accessibility: accessibility, flags: constraints.union(.privateKeyUsage))
        )
        return attributes
    }

    /// The dictionary for `SecKeyCreateRandomKey`.
    ///
    /// The context goes at the top level. The framework merges the top level into the private
    /// key's attributes before it adds the key, and reads the context for a token key from the
    /// parameters as given (Security sources, `SecKey.m` and `SecCTKKey.m`).
    package func generationDictionary(
        for keyType: KeyType,
        sizeInBits: Int,
        attributes: Attributes<CryptographicKey>,
        authenticationContext: AuthenticationContext?,
    ) -> SecDictionary {
        var dictionary = generationDictionary(for: keyType, sizeInBits: sizeInBits, attributes: attributes)
        authenticationContext?.apply(to: &dictionary)
        return dictionary
    }

    /// The dictionary for `SecKeyCreateRandomKey`, before any authentication context.
    ///
    /// Everything about the stored key goes under `kSecPrivateKeyAttrs`. Set at the top level the
    /// same attributes apply to the public key too, which the framework then stores next to the
    /// private one (measured on both keychain implementations). The token is the exception:
    /// `SecKey.h` allows `kSecAttrTokenID` only at the top level.
    package func generationDictionary(
        for keyType: KeyType,
        sizeInBits: Int,
        attributes: Attributes<CryptographicKey>,
    ) -> SecDictionary {
        var privateKey = attributes.secDictionary
        privateKey[.keyType] = nil
        privateKey[.keySizeInBits] = nil
        privateKey[.isPermanent] = .bool(true)
        if let accessGroup, privateKey[.accessGroup] == nil {
            privateKey[.accessGroup] = .string(accessGroup.rawValue)
        }

        var dictionary: SecDictionary = [
            .keyType: SecValue(constant: keyType),
            .keySizeInBits: .integer(Int64(sizeInBits)),
        ]
        dictionary[.tokenID] = privateKey.removeValue(forKey: .tokenID)
        dictionary[.privateKeyAttrs] = .dictionary(privateKey)
        switch storage {
        case .dataProtection:
            dictionary[.useDataProtectionKeychain] = .bool(true)
        #if os(macOS)
        case .fileBased(let keychain):
            // Without the key the framework generates the key in the data protection keychain
            // when its attributes cannot live here (Security sources, `SecKey.cpp`).
            dictionary[.useDataProtectionKeychain] = .bool(false)
            if let keychain {
                dictionary[.useKeychain] = .object(SecObject(keychain.reference))
            }
        #endif
        }
        return dictionary
    }
}
