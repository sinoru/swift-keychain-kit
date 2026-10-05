//
//  KeyReference+Operations.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

// The functions of `SecKey.h`. Each reports failure through a `CFError` out-parameter that the
// caller owns, which strict memory safety classifies as unsafe, hence the `unsafe` markers.
// Security reports these failures in the `OSStatus` domain, and a key that lives on a token in
// the token's own, both of which surface as `KeychainError`.

// MARK: - Creating keys

extension KeyReference {
    /// Generates a private key that is not stored in a keychain (`SecKeyCreateRandomKey`).
    ///
    /// Use `Keychain/generateKey(_:sizeInBits:attributes:)` for a key that is.
    public init(generating keyType: KeyType, sizeInBits: Int) throws(KeychainError) {
        try self.init(generatingWith: [
            .keyType: SecValue(constant: keyType),
            .keySizeInBits: .integer(Int64(sizeInBits)),
        ])
    }

    /// `SecKeyCreateRandomKey` over a `SecDictionary`.
    package init(generatingWith parameters: SecDictionary) throws(KeychainError) {
        var error: Unmanaged<CFError>?
        let key = unsafe SecKeyCreateRandomKey(parameters.cfDictionary, &error)
        self.init(reference: try unsafe Self.unwrap(key, error))
    }

    /// Creates a key from its external representation (`SecKeyCreateWithData`).
    ///
    /// The format depends on the type: PKCS #1 for an RSA key, where a public key may also be in
    /// X.509 form, and ANSI X9.63 (`04 || X || Y [|| K]`) for an elliptic curve key. The key is
    /// not added to a keychain.
    public init(externalRepresentation data: Data, keyType: KeyType, keyClass: KeyClass) throws(KeychainError) {
        let attributes: SecDictionary = [
            .keyType: SecValue(constant: keyType),
            .keyClass: SecValue(constant: keyClass),
        ]
        var error: Unmanaged<CFError>?
        let key = unsafe SecKeyCreateWithData(data as CFData, attributes.cfDictionary, &error)
        self.init(reference: try unsafe Self.unwrap(key, error))
    }
}

// MARK: - Deriving and exporting

extension KeyReference {
    /// The public key of a private key or key pair (`SecKeyCopyPublicKey`), or `nil` when none
    /// can be computed from this key. A public key yields itself.
    public var publicKey: KeyReference? {
        SecKeyCopyPublicKey(reference).map(KeyReference.init(reference:))
    }

    /// The key in the format suited to its type (`SecKeyCopyExternalRepresentation`): PKCS #1 for
    /// an RSA key, ANSI X9.63 (`04 || X || Y [|| K]`) for an elliptic curve key.
    ///
    /// Fails for a key that cannot be exported, such as one bound to the Secure Enclave.
    public func externalRepresentation() throws(KeychainError) -> Data {
        var error: Unmanaged<CFError>?
        let data = unsafe SecKeyCopyExternalRepresentation(reference, &error)
        return try unsafe Self.unwrap(data, error) as Data
    }
}

// MARK: - Operations

extension KeyReference {
    /// Whether the key can perform `operation` with `algorithm` (`SecKeyIsAlgorithmSupported`).
    public func supports(_ algorithm: KeyAlgorithm, for operation: KeyOperation) -> Bool {
        SecKeyIsAlgorithmSupported(reference, operation.secKeyOperationType, algorithm.secKeyAlgorithm)
    }

    /// The signature of `data` made with this private key (`SecKeyCreateSignature`).
    ///
    /// The algorithm decides whether `data` is the message or a digest of it, and the format of
    /// the signature.
    ///
    /// A key whose access control asks for the user makes this call wait until they
    /// authenticate. It throws `userCanceled` when they dismiss the prompt, and
    /// `interactionNotAllowed` when the key's authentication context forbids one. Use the
    /// `async` form to keep the wait off the caller's actor.
    public func signature(for data: Data, using algorithm: KeyAlgorithm) throws(KeychainError) -> Data {
        var error: Unmanaged<CFError>?
        let signature = unsafe SecKeyCreateSignature(reference, algorithm.secKeyAlgorithm, data as CFData, &error)
        return try unsafe Self.unwrap(signature, error) as Data
    }

    /// Whether `signature` is this public key's signature of `data` (`SecKeyVerifySignature`).
    ///
    /// A signature that does not match, or is malformed, is `false`. Anything else that keeps
    /// the framework from judging, such as an algorithm the key does not support, is thrown.
    public func isValidSignature(_ signature: Data, for data: Data, using algorithm: KeyAlgorithm) throws(KeychainError) -> Bool {
        var error: Unmanaged<CFError>?
        if unsafe SecKeyVerifySignature(reference, algorithm.secKeyAlgorithm, data as CFData, signature as CFData, &error) {
            return true
        }
        let failure = KeychainError(cfError: unsafe error?.takeRetainedValue())
        // A mismatch is `errSecVerifyFailed` and a malformed signature is
        // `errSecInvalidSignature` (measured on macOS 26).
        guard failure.status == errSecVerifyFailed || failure.status == errSecInvalidSignature else {
            throw failure
        }
        return false
    }

    /// `plaintext` encrypted with this public key (`SecKeyCreateEncryptedData`).
    public func encryptedData(for plaintext: Data, using algorithm: KeyAlgorithm) throws(KeychainError) -> Data {
        var error: Unmanaged<CFError>?
        let ciphertext = unsafe SecKeyCreateEncryptedData(reference, algorithm.secKeyAlgorithm, plaintext as CFData, &error)
        return try unsafe Self.unwrap(ciphertext, error) as Data
    }

    /// `ciphertext` decrypted with this private key (`SecKeyCreateDecryptedData`).
    ///
    /// Waits for the user and fails as `signature(for:using:)` does when the key's access
    /// control asks for them.
    public func decryptedData(for ciphertext: Data, using algorithm: KeyAlgorithm) throws(KeychainError) -> Data {
        var error: Unmanaged<CFError>?
        let plaintext = unsafe SecKeyCreateDecryptedData(reference, algorithm.secKeyAlgorithm, ciphertext as CFData, &error)
        return try unsafe Self.unwrap(plaintext, error) as Data
    }

    /// The result of a Diffie-Hellman key exchange between this private key and the other
    /// party's `publicKey` (`SecKeyCopyKeyExchangeResult`).
    ///
    /// An algorithm with a key derivation function requires `requestedSize`, the length of the
    /// result in bytes, and accepts `sharedInfo`. The plain algorithms take neither.
    ///
    /// Waits for the user and fails as `signature(for:using:)` does when the key's access
    /// control asks for them.
    public func keyExchangeResult(
        with publicKey: KeyReference,
        using algorithm: KeyAlgorithm,
        requestedSize: Int? = nil,
        sharedInfo: Data? = nil,
    ) throws(KeychainError) -> Data {
        var parameters: SecDictionary = [:]
        if let requestedSize {
            parameters[.keyExchangeRequestedSize] = .integer(Int64(requestedSize))
        }
        if let sharedInfo {
            parameters[.keyExchangeSharedInfo] = .data(sharedInfo)
        }
        var error: Unmanaged<CFError>?
        let result = unsafe SecKeyCopyKeyExchangeResult(
            reference,
            algorithm.secKeyAlgorithm,
            publicKey.reference,
            parameters.cfDictionary,
            &error,
        )
        return try unsafe Self.unwrap(result, error) as Data
    }

    /// The value a `SecKey` function returned, or the error it reported in its place.
    private static func unwrap<Value>(_ value: Value?, _ error: Unmanaged<CFError>?) throws(KeychainError) -> Value {
        guard let value else {
            throw KeychainError(cfError: unsafe error?.takeRetainedValue())
        }
        return value
    }
}
