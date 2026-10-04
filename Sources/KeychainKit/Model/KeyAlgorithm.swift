//
//  KeyAlgorithm.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// An algorithm for an operation with a key, one of the `kSecKeyAlgorithm*` constants.
///
/// The name of each constant says what it expects. A `Digest` signature algorithm takes a digest
/// the caller computed, a `Message` algorithm hashes the input itself, and an `X963SHA*` key
/// exchange algorithm runs the shared secret through the ANSI X9.63 key derivation function.
/// `KeyReference/supports(_:for:)` reports whether a key can perform an operation with one.
public struct KeyAlgorithm: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    private init(_ algorithm: SecKeyAlgorithm) {
        rawValue = algorithm.rawValue as String
    }

    /// The framework's form of the algorithm.
    var secKeyAlgorithm: SecKeyAlgorithm {
        SecKeyAlgorithm(rawValue: rawValue as CFString)
    }
}

// MARK: - RSA signatures

extension KeyAlgorithm {
    /// `kSecKeyAlgorithmRSASignatureRaw`
    public static let rsaSignatureRaw = KeyAlgorithm(.rsaSignatureRaw)

    /// `kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw`
    public static let rsaSignatureDigestPKCS1v15Raw = KeyAlgorithm(.rsaSignatureDigestPKCS1v15Raw)

    /// `kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1`
    public static let rsaSignatureDigestPKCS1v15SHA1 = KeyAlgorithm(.rsaSignatureDigestPKCS1v15SHA1)

    /// `kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224`
    public static let rsaSignatureDigestPKCS1v15SHA224 = KeyAlgorithm(.rsaSignatureDigestPKCS1v15SHA224)

    /// `kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256`
    public static let rsaSignatureDigestPKCS1v15SHA256 = KeyAlgorithm(.rsaSignatureDigestPKCS1v15SHA256)

    /// `kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384`
    public static let rsaSignatureDigestPKCS1v15SHA384 = KeyAlgorithm(.rsaSignatureDigestPKCS1v15SHA384)

    /// `kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512`
    public static let rsaSignatureDigestPKCS1v15SHA512 = KeyAlgorithm(.rsaSignatureDigestPKCS1v15SHA512)

    /// `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1`
    public static let rsaSignatureMessagePKCS1v15SHA1 = KeyAlgorithm(.rsaSignatureMessagePKCS1v15SHA1)

    /// `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224`
    public static let rsaSignatureMessagePKCS1v15SHA224 = KeyAlgorithm(.rsaSignatureMessagePKCS1v15SHA224)

    /// `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256`
    public static let rsaSignatureMessagePKCS1v15SHA256 = KeyAlgorithm(.rsaSignatureMessagePKCS1v15SHA256)

    /// `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384`
    public static let rsaSignatureMessagePKCS1v15SHA384 = KeyAlgorithm(.rsaSignatureMessagePKCS1v15SHA384)

    /// `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512`
    public static let rsaSignatureMessagePKCS1v15SHA512 = KeyAlgorithm(.rsaSignatureMessagePKCS1v15SHA512)

    /// `kSecKeyAlgorithmRSASignatureDigestPSSSHA1`
    public static let rsaSignatureDigestPSSSHA1 = KeyAlgorithm(.rsaSignatureDigestPSSSHA1)

    /// `kSecKeyAlgorithmRSASignatureDigestPSSSHA224`
    public static let rsaSignatureDigestPSSSHA224 = KeyAlgorithm(.rsaSignatureDigestPSSSHA224)

    /// `kSecKeyAlgorithmRSASignatureDigestPSSSHA256`
    public static let rsaSignatureDigestPSSSHA256 = KeyAlgorithm(.rsaSignatureDigestPSSSHA256)

    /// `kSecKeyAlgorithmRSASignatureDigestPSSSHA384`
    public static let rsaSignatureDigestPSSSHA384 = KeyAlgorithm(.rsaSignatureDigestPSSSHA384)

    /// `kSecKeyAlgorithmRSASignatureDigestPSSSHA512`
    public static let rsaSignatureDigestPSSSHA512 = KeyAlgorithm(.rsaSignatureDigestPSSSHA512)

    /// `kSecKeyAlgorithmRSASignatureMessagePSSSHA1`
    public static let rsaSignatureMessagePSSSHA1 = KeyAlgorithm(.rsaSignatureMessagePSSSHA1)

    /// `kSecKeyAlgorithmRSASignatureMessagePSSSHA224`
    public static let rsaSignatureMessagePSSSHA224 = KeyAlgorithm(.rsaSignatureMessagePSSSHA224)

    /// `kSecKeyAlgorithmRSASignatureMessagePSSSHA256`
    public static let rsaSignatureMessagePSSSHA256 = KeyAlgorithm(.rsaSignatureMessagePSSSHA256)

    /// `kSecKeyAlgorithmRSASignatureMessagePSSSHA384`
    public static let rsaSignatureMessagePSSSHA384 = KeyAlgorithm(.rsaSignatureMessagePSSSHA384)

    /// `kSecKeyAlgorithmRSASignatureMessagePSSSHA512`
    public static let rsaSignatureMessagePSSSHA512 = KeyAlgorithm(.rsaSignatureMessagePSSSHA512)
}

// MARK: - ECDSA signatures

extension KeyAlgorithm {
    /// `kSecKeyAlgorithmECDSASignatureDigestX962`
    public static let ecdsaSignatureDigestX962 = KeyAlgorithm(.ecdsaSignatureDigestX962)

    /// `kSecKeyAlgorithmECDSASignatureDigestX962SHA1`
    public static let ecdsaSignatureDigestX962SHA1 = KeyAlgorithm(.ecdsaSignatureDigestX962SHA1)

    /// `kSecKeyAlgorithmECDSASignatureDigestX962SHA224`
    public static let ecdsaSignatureDigestX962SHA224 = KeyAlgorithm(.ecdsaSignatureDigestX962SHA224)

    /// `kSecKeyAlgorithmECDSASignatureDigestX962SHA256`
    public static let ecdsaSignatureDigestX962SHA256 = KeyAlgorithm(.ecdsaSignatureDigestX962SHA256)

    /// `kSecKeyAlgorithmECDSASignatureDigestX962SHA384`
    public static let ecdsaSignatureDigestX962SHA384 = KeyAlgorithm(.ecdsaSignatureDigestX962SHA384)

    /// `kSecKeyAlgorithmECDSASignatureDigestX962SHA512`
    public static let ecdsaSignatureDigestX962SHA512 = KeyAlgorithm(.ecdsaSignatureDigestX962SHA512)

    /// `kSecKeyAlgorithmECDSASignatureMessageX962SHA1`
    public static let ecdsaSignatureMessageX962SHA1 = KeyAlgorithm(.ecdsaSignatureMessageX962SHA1)

    /// `kSecKeyAlgorithmECDSASignatureMessageX962SHA224`
    public static let ecdsaSignatureMessageX962SHA224 = KeyAlgorithm(.ecdsaSignatureMessageX962SHA224)

    /// `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`
    public static let ecdsaSignatureMessageX962SHA256 = KeyAlgorithm(.ecdsaSignatureMessageX962SHA256)

    /// `kSecKeyAlgorithmECDSASignatureMessageX962SHA384`
    public static let ecdsaSignatureMessageX962SHA384 = KeyAlgorithm(.ecdsaSignatureMessageX962SHA384)

    /// `kSecKeyAlgorithmECDSASignatureMessageX962SHA512`
    public static let ecdsaSignatureMessageX962SHA512 = KeyAlgorithm(.ecdsaSignatureMessageX962SHA512)

    /// `kSecKeyAlgorithmECDSASignatureDigestRFC4754`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureDigestRFC4754 = KeyAlgorithm(.ecdsaSignatureDigestRFC4754)

    /// `kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA1`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureDigestRFC4754SHA1 = KeyAlgorithm(.ecdsaSignatureDigestRFC4754SHA1)

    /// `kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA224`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureDigestRFC4754SHA224 = KeyAlgorithm(.ecdsaSignatureDigestRFC4754SHA224)

    /// `kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureDigestRFC4754SHA256 = KeyAlgorithm(.ecdsaSignatureDigestRFC4754SHA256)

    /// `kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureDigestRFC4754SHA384 = KeyAlgorithm(.ecdsaSignatureDigestRFC4754SHA384)

    /// `kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureDigestRFC4754SHA512 = KeyAlgorithm(.ecdsaSignatureDigestRFC4754SHA512)

    /// `kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA1`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureMessageRFC4754SHA1 = KeyAlgorithm(.ecdsaSignatureMessageRFC4754SHA1)

    /// `kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA224`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureMessageRFC4754SHA224 = KeyAlgorithm(.ecdsaSignatureMessageRFC4754SHA224)

    /// `kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureMessageRFC4754SHA256 = KeyAlgorithm(.ecdsaSignatureMessageRFC4754SHA256)

    /// `kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureMessageRFC4754SHA384 = KeyAlgorithm(.ecdsaSignatureMessageRFC4754SHA384)

    /// `kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512`
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public static let ecdsaSignatureMessageRFC4754SHA512 = KeyAlgorithm(.ecdsaSignatureMessageRFC4754SHA512)

    /// `kSecKeyAlgorithmECDSASignatureRFC4754`
    @available(macOS, deprecated: 14.0, renamed: "ecdsaSignatureDigestRFC4754")
    @available(iOS, deprecated: 17.0, renamed: "ecdsaSignatureDigestRFC4754")
    @available(tvOS, deprecated: 17.0, renamed: "ecdsaSignatureDigestRFC4754")
    @available(watchOS, deprecated: 10.0, renamed: "ecdsaSignatureDigestRFC4754")
    @available(visionOS, deprecated: 1.0, renamed: "ecdsaSignatureDigestRFC4754")
    public static let ecdsaSignatureRFC4754 = KeyAlgorithm(.ecdsaSignatureRFC4754)
}

// MARK: - RSA encryption

extension KeyAlgorithm {
    /// `kSecKeyAlgorithmRSAEncryptionRaw`
    public static let rsaEncryptionRaw = KeyAlgorithm(.rsaEncryptionRaw)

    /// `kSecKeyAlgorithmRSAEncryptionPKCS1`
    public static let rsaEncryptionPKCS1 = KeyAlgorithm(.rsaEncryptionPKCS1)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA1`
    public static let rsaEncryptionOAEPSHA1 = KeyAlgorithm(.rsaEncryptionOAEPSHA1)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA224`
    public static let rsaEncryptionOAEPSHA224 = KeyAlgorithm(.rsaEncryptionOAEPSHA224)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA256`
    public static let rsaEncryptionOAEPSHA256 = KeyAlgorithm(.rsaEncryptionOAEPSHA256)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA384`
    public static let rsaEncryptionOAEPSHA384 = KeyAlgorithm(.rsaEncryptionOAEPSHA384)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA512`
    public static let rsaEncryptionOAEPSHA512 = KeyAlgorithm(.rsaEncryptionOAEPSHA512)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM`
    public static let rsaEncryptionOAEPSHA1AESGCM = KeyAlgorithm(.rsaEncryptionOAEPSHA1AESGCM)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM`
    public static let rsaEncryptionOAEPSHA224AESGCM = KeyAlgorithm(.rsaEncryptionOAEPSHA224AESGCM)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM`
    public static let rsaEncryptionOAEPSHA256AESGCM = KeyAlgorithm(.rsaEncryptionOAEPSHA256AESGCM)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM`
    public static let rsaEncryptionOAEPSHA384AESGCM = KeyAlgorithm(.rsaEncryptionOAEPSHA384AESGCM)

    /// `kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM`
    public static let rsaEncryptionOAEPSHA512AESGCM = KeyAlgorithm(.rsaEncryptionOAEPSHA512AESGCM)
}

// MARK: - ECIES encryption

extension KeyAlgorithm {
    /// `kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM`
    public static let eciesEncryptionStandardX963SHA1AESGCM = KeyAlgorithm(.eciesEncryptionStandardX963SHA1AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM`
    public static let eciesEncryptionStandardX963SHA224AESGCM = KeyAlgorithm(.eciesEncryptionStandardX963SHA224AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM`
    public static let eciesEncryptionStandardX963SHA256AESGCM = KeyAlgorithm(.eciesEncryptionStandardX963SHA256AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM`
    public static let eciesEncryptionStandardX963SHA384AESGCM = KeyAlgorithm(.eciesEncryptionStandardX963SHA384AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM`
    public static let eciesEncryptionStandardX963SHA512AESGCM = KeyAlgorithm(.eciesEncryptionStandardX963SHA512AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM`
    public static let eciesEncryptionCofactorX963SHA1AESGCM = KeyAlgorithm(.eciesEncryptionCofactorX963SHA1AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM`
    public static let eciesEncryptionCofactorX963SHA224AESGCM = KeyAlgorithm(.eciesEncryptionCofactorX963SHA224AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM`
    public static let eciesEncryptionCofactorX963SHA256AESGCM = KeyAlgorithm(.eciesEncryptionCofactorX963SHA256AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM`
    public static let eciesEncryptionCofactorX963SHA384AESGCM = KeyAlgorithm(.eciesEncryptionCofactorX963SHA384AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM`
    public static let eciesEncryptionCofactorX963SHA512AESGCM = KeyAlgorithm(.eciesEncryptionCofactorX963SHA512AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM`
    public static let eciesEncryptionStandardVariableIVX963SHA224AESGCM = KeyAlgorithm(.eciesEncryptionStandardVariableIVX963SHA224AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM`
    public static let eciesEncryptionStandardVariableIVX963SHA256AESGCM = KeyAlgorithm(.eciesEncryptionStandardVariableIVX963SHA256AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM`
    public static let eciesEncryptionStandardVariableIVX963SHA384AESGCM = KeyAlgorithm(.eciesEncryptionStandardVariableIVX963SHA384AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM`
    public static let eciesEncryptionStandardVariableIVX963SHA512AESGCM = KeyAlgorithm(.eciesEncryptionStandardVariableIVX963SHA512AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM`
    public static let eciesEncryptionCofactorVariableIVX963SHA224AESGCM = KeyAlgorithm(.eciesEncryptionCofactorVariableIVX963SHA224AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`
    public static let eciesEncryptionCofactorVariableIVX963SHA256AESGCM = KeyAlgorithm(.eciesEncryptionCofactorVariableIVX963SHA256AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM`
    public static let eciesEncryptionCofactorVariableIVX963SHA384AESGCM = KeyAlgorithm(.eciesEncryptionCofactorVariableIVX963SHA384AESGCM)

    /// `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM`
    public static let eciesEncryptionCofactorVariableIVX963SHA512AESGCM = KeyAlgorithm(.eciesEncryptionCofactorVariableIVX963SHA512AESGCM)
}

// MARK: - ECDH key exchange

extension KeyAlgorithm {
    /// `kSecKeyAlgorithmECDHKeyExchangeStandard`
    public static let ecdhKeyExchangeStandard = KeyAlgorithm(.ecdhKeyExchangeStandard)

    /// `kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1`
    public static let ecdhKeyExchangeStandardX963SHA1 = KeyAlgorithm(.ecdhKeyExchangeStandardX963SHA1)

    /// `kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224`
    public static let ecdhKeyExchangeStandardX963SHA224 = KeyAlgorithm(.ecdhKeyExchangeStandardX963SHA224)

    /// `kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256`
    public static let ecdhKeyExchangeStandardX963SHA256 = KeyAlgorithm(.ecdhKeyExchangeStandardX963SHA256)

    /// `kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384`
    public static let ecdhKeyExchangeStandardX963SHA384 = KeyAlgorithm(.ecdhKeyExchangeStandardX963SHA384)

    /// `kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512`
    public static let ecdhKeyExchangeStandardX963SHA512 = KeyAlgorithm(.ecdhKeyExchangeStandardX963SHA512)

    /// `kSecKeyAlgorithmECDHKeyExchangeCofactor`
    public static let ecdhKeyExchangeCofactor = KeyAlgorithm(.ecdhKeyExchangeCofactor)

    /// `kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1`
    public static let ecdhKeyExchangeCofactorX963SHA1 = KeyAlgorithm(.ecdhKeyExchangeCofactorX963SHA1)

    /// `kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224`
    public static let ecdhKeyExchangeCofactorX963SHA224 = KeyAlgorithm(.ecdhKeyExchangeCofactorX963SHA224)

    /// `kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256`
    public static let ecdhKeyExchangeCofactorX963SHA256 = KeyAlgorithm(.ecdhKeyExchangeCofactorX963SHA256)

    /// `kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384`
    public static let ecdhKeyExchangeCofactorX963SHA384 = KeyAlgorithm(.ecdhKeyExchangeCofactorX963SHA384)

    /// `kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512`
    public static let ecdhKeyExchangeCofactorX963SHA512 = KeyAlgorithm(.ecdhKeyExchangeCofactorX963SHA512)
}
