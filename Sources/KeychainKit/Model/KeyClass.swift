//
//  KeyClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The kind of a cryptographic key, one of the `kSecAttrKeyClass*` constants.
public struct KeyClass: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// `kSecAttrKeyClassPublic`
    public static let `public` = KeyClass(kSecAttrKeyClassPublic)

    /// `kSecAttrKeyClassPrivate`
    public static let `private` = KeyClass(kSecAttrKeyClassPrivate)

    /// `kSecAttrKeyClassSymmetric`
    public static let symmetric = KeyClass(kSecAttrKeyClassSymmetric)

    private init(_ constant: CFString) {
        rawValue = constant as String
    }
}
