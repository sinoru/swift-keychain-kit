//
//  CertificateReference+Contents.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

extension CertificateReference {
    /// Creates a certificate from its DER encoding (`SecCertificateCreateWithData`), or returns
    /// `nil` when `data` is not a valid DER-encoded X.509 certificate.
    ///
    /// The framework reports no reason for a rejection, which is why this is a failable
    /// initializer rather than a throwing one. The certificate is not added to a keychain.
    public init?(derRepresentation data: Data) {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            return nil
        }
        self.init(reference: certificate)
    }

    /// The DER encoding of the certificate (`SecCertificateCopyData`).
    public var derRepresentation: Data {
        SecCertificateCopyData(reference) as Data
    }

    /// The public key the certificate certifies (`SecCertificateCopyKey`), or `nil` when its
    /// algorithm or encoding is not supported.
    public var publicKey: KeyReference? {
        SecCertificateCopyKey(reference).map(KeyReference.init(reference:))
    }
}
