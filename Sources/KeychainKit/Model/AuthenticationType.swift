//
//  AuthenticationType.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The authentication scheme of an internet password, one of the
/// `kSecAttrAuthenticationType*` constants.
public struct AuthenticationType: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let ntlm = AuthenticationType(kSecAttrAuthenticationTypeNTLM)
    public static let msn = AuthenticationType(kSecAttrAuthenticationTypeMSN)
    public static let dpa = AuthenticationType(kSecAttrAuthenticationTypeDPA)
    public static let rpa = AuthenticationType(kSecAttrAuthenticationTypeRPA)
    public static let httpBasic = AuthenticationType(kSecAttrAuthenticationTypeHTTPBasic)
    public static let httpDigest = AuthenticationType(kSecAttrAuthenticationTypeHTTPDigest)
    public static let htmlForm = AuthenticationType(kSecAttrAuthenticationTypeHTMLForm)
    public static let `default` = AuthenticationType(kSecAttrAuthenticationTypeDefault)

    private init(_ constant: CFString) {
        rawValue = constant as String
    }
}
