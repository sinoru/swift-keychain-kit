//
//  TokenID.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The token that holds a key outside the keychain database, one of the `kSecAttrTokenID*` constants.
public struct TokenID: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// `kSecAttrTokenIDSecureEnclave`: the private key lives in the Secure Enclave.
    public static let secureEnclave = TokenID(kSecAttrTokenIDSecureEnclave)

    private init(_ constant: CFString) {
        rawValue = constant as String
    }
}
