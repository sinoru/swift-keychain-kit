//
//  KeyReference+Async.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

/// Asynchronous forms of the operations that can take long.
///
/// An operation with a key stored in a keychain or the Secure Enclave goes through IPC and may
/// wait for the user to authenticate, and generating a large key is slow on its own. As with
/// `Keychain`, `@concurrent` moves each call off the caller's actor, and a call in flight runs
/// to completion.
///
/// In an asynchronous context the compiler always picks these overloads (SE-0296), so each
/// body reaches the synchronous implementation through a function reference with an explicit
/// synchronous type.
extension KeyReference {
    /// The asynchronous form of ``init(generating:sizeInBits:)``.
    @concurrent
    public init(generating keyType: KeyType, sizeInBits: Int) async throws(KeychainError) {
        let synchronous: (KeyType, Int) throws(KeychainError) -> KeyReference = KeyReference.init(generating:sizeInBits:)
        self = try synchronous(keyType, sizeInBits)
    }

    /// The asynchronous form of ``externalRepresentation()``.
    @concurrent
    public func externalRepresentation() async throws(KeychainError) -> Data {
        let synchronous: () throws(KeychainError) -> Data = externalRepresentation
        return try synchronous()
    }

    /// The asynchronous form of ``signature(for:using:)``.
    @concurrent
    public func signature(for data: Data, using algorithm: KeyAlgorithm) async throws(KeychainError) -> Data {
        let synchronous: (Data, KeyAlgorithm) throws(KeychainError) -> Data = signature(for:using:)
        return try synchronous(data, algorithm)
    }

    /// The asynchronous form of ``isValidSignature(_:for:using:)``.
    @concurrent
    public func isValidSignature(_ signature: Data, for data: Data, using algorithm: KeyAlgorithm) async throws(KeychainError) -> Bool {
        let synchronous: (Data, Data, KeyAlgorithm) throws(KeychainError) -> Bool = isValidSignature(_:for:using:)
        return try synchronous(signature, data, algorithm)
    }

    /// The asynchronous form of ``encryptedData(for:using:)``.
    @concurrent
    public func encryptedData(for plaintext: Data, using algorithm: KeyAlgorithm) async throws(KeychainError) -> Data {
        let synchronous: (Data, KeyAlgorithm) throws(KeychainError) -> Data = encryptedData(for:using:)
        return try synchronous(plaintext, algorithm)
    }

    /// The asynchronous form of ``decryptedData(for:using:)``.
    @concurrent
    public func decryptedData(for ciphertext: Data, using algorithm: KeyAlgorithm) async throws(KeychainError) -> Data {
        let synchronous: (Data, KeyAlgorithm) throws(KeychainError) -> Data = decryptedData(for:using:)
        return try synchronous(ciphertext, algorithm)
    }

    /// The asynchronous form of ``keyExchangeResult(with:using:requestedSize:sharedInfo:)``.
    @concurrent
    public func keyExchangeResult(
        with publicKey: KeyReference,
        using algorithm: KeyAlgorithm,
        requestedSize: Int? = nil,
        sharedInfo: Data? = nil,
    ) async throws(KeychainError) -> Data {
        let synchronous: (KeyReference, KeyAlgorithm, Int?, Data?) throws(KeychainError) -> Data = keyExchangeResult(with:using:requestedSize:sharedInfo:)
        return try synchronous(publicKey, algorithm, requestedSize, sharedInfo)
    }
}
