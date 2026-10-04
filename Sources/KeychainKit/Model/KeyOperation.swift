//
//  KeyOperation.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// An operation a key can perform, mirroring `SecKeyOperationType`.
public enum KeyOperation: Hashable, Sendable {
    /// `KeyReference/signature(for:using:)`
    case sign

    /// `KeyReference/isValidSignature(_:for:using:)`
    case verify

    /// `KeyReference/encryptedData(for:using:)`
    case encrypt

    /// `KeyReference/decryptedData(for:using:)`
    case decrypt

    /// `KeyReference/keyExchangeResult(with:using:requestedSize:sharedInfo:)`
    case keyExchange

    /// The framework's form of the operation.
    var secKeyOperationType: SecKeyOperationType {
        switch self {
        case .sign: .sign
        case .verify: .verify
        case .encrypt: .encrypt
        case .decrypt: .decrypt
        case .keyExchange: .keyExchange
        }
    }
}
