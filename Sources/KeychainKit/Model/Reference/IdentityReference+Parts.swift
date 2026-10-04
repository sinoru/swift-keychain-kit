//
//  IdentityReference+Parts.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

// Both functions return their result through an out-pointer, which strict memory safety
// classifies as unsafe, hence the `unsafe` markers.

extension IdentityReference {
    /// The certificate of the identity (`SecIdentityCopyCertificate`).
    public func certificate() throws(KeychainError) -> CertificateReference {
        var certificate: SecCertificate?
        try KeychainError.check(unsafe SecIdentityCopyCertificate(reference, &certificate))
        guard let certificate else {
            throw KeychainError(code: .decodingFailed)
        }
        return CertificateReference(reference: certificate)
    }

    /// The private key of the identity (`SecIdentityCopyPrivateKey`).
    public func privateKey() throws(KeychainError) -> KeyReference {
        var key: SecKey?
        try KeychainError.check(unsafe SecIdentityCopyPrivateKey(reference, &key))
        guard let key else {
            throw KeychainError(code: .decodingFailed)
        }
        return KeyReference(reference: key)
    }
}
