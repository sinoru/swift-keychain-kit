//
//  KeyType.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The algorithm of a cryptographic key, one of the `kSecAttrKeyType*` constants.
public struct KeyType: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// `kSecAttrKeyTypeRSA`
    public static let rsa = KeyType(kSecAttrKeyTypeRSA)

    /// `kSecAttrKeyTypeECSECPrimeRandom`: an elliptic curve key on a NIST P curve.
    public static let ecSECPrimeRandom = KeyType(kSecAttrKeyTypeECSECPrimeRandom)

    private init(_ constant: CFString) {
        rawValue = constant as String
    }
}
