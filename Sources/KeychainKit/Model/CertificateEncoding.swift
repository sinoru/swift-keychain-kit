//
//  CertificateEncoding.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The encoding of a certificate (`kSecAttrCertificateEncoding`).
///
/// DER is the only encoding the data protection keychain supports. The file-based keychain on
/// macOS uses the `CSSM_CERT_ENCODING` values.
public struct CertificateEncoding: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// DER.
    public static let der = CertificateEncoding(rawValue: 3)
}
