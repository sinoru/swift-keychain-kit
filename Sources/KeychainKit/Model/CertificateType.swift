//
//  CertificateType.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The type of a certificate (`kSecAttrCertificateType`).
///
/// On the data protection keychain the value is the X.509 version of the certificate. The
/// file-based keychain on macOS uses the `CSSM_CERT_TYPE` values instead, and does not report
/// the version through them: for the same version 3 certificate the data protection keychain
/// gives 3 and the file-based keychain gives 1 (measured on the iOS 27 simulator and macOS 26).
public struct CertificateType: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// X.509 version 1.
    public static let x509v1 = CertificateType(rawValue: 1)

    /// X.509 version 2.
    public static let x509v2 = CertificateType(rawValue: 2)

    /// X.509 version 3.
    public static let x509v3 = CertificateType(rawValue: 3)
}
