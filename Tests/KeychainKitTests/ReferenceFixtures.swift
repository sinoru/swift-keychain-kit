//
//  ReferenceFixtures.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Security

import KeychainKit

/// Keys and a certificate for the tests of the reference item classes.
///
/// The certificate is self-signed over the fixture key (P-256, subject `CN=KeychainKit Test`),
/// generated once with OpenSSL. Neither protects anything.
enum ReferenceFixtures {
    /// The fixture private key, the one the fixture certificate certifies, as OpenSSL wrote it.
    static let privateKeyPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIJR5j/HZOmYOCfY1ZvbDLbYl/NptoYDBwImQKxBhB4E4oAoGCCqGSM49
        AwEHoUQDQgAE/6r5qRnCMUbioZz7v/jNJYQLX6TyvrIbvv5qhXL0CA/JIV4ioyJC
        PAvx/qDOdNBydoqy3nxnzTVQJFQI8P4pWg==
        -----END EC PRIVATE KEY-----
        """

    /// The fixture private key in ANSI X9.63 form: `04 || X || Y || K`. The data protection
    /// keychain accepts a key made from it, which the file-based keychain does not.
    static let privateKeyData = Data(base64Encoded: "BP+q+akZwjFG4qGc+7/4zSWEC1+k8r6yG77+aoVy9AgPySFeIqMiQjwL8f6gznTQcnaKst58Z801UCRUCPD+KVqUeY/x2TpmDgn2NWb2wy22JfzabaGAwcCJkCsQYQeBOA==")!

    /// The public half of the fixture key in ANSI X9.63 form: `04 || X || Y`.
    static let publicKeyData = Data(base64Encoded: "BP+q+akZwjFG4qGc+7/4zSWEC1+k8r6yG77+aoVy9AgPySFeIqMiQjwL8f6gznTQcnaKst58Z801UCRUCPD+KVo=")!

    /// The fixture certificate, DER-encoded.
    static let certificateData = Data(base64Encoded: "MIIBjDCCATOgAwIBAgIUC6VV5sBPiUFd0OArSCc0CxX/3Q0wCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQS2V5Y2hhaW5LaXQgVGVzdDAgFw0yNjEwMDMxNTAxMjdaGA8yMTI2MDkwOTE1MDEyN1owGzEZMBcGA1UEAwwQS2V5Y2hhaW5LaXQgVGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP+q+akZwjFG4qGc+7/4zSWEC1+k8r6yG77+aoVy9AgPySFeIqMiQjwL8f6gznTQcnaKst58Z801UCRUCPD+KVqjUzBRMB0GA1UdDgQWBBS0SoiF6iEOybnVhXmIKXATUnI7hzAfBgNVHSMEGDAWgBS0SoiF6iEOybnVhXmIKXATUnI7hzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFbUeZ+5RbNjEV2AemuIT92kxtLoKs/bZ3qQG0q2rTesAiAzzfO8oTnCkd0Jga3SyV8TxOlQC/So1W4WpFyn8Bt5TA==")!

    /// A fresh P-256 private key that is not stored anywhere.
    static func makeKey() throws -> KeyReference {
        var error: Unmanaged<CFError>?
        let key = unsafe SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ] as CFDictionary, &error)
        return try unsafe reference(key, error)
    }

    static func makeCertificate() throws -> CertificateReference {
        guard let certificate = CertificateReference(derRepresentation: certificateData) else {
            throw KeychainError(code: .decodingFailed)
        }
        return certificate
    }

    private static func reference(_ key: SecKey?, _ error: Unmanaged<CFError>?) throws -> KeyReference {
        guard let key else {
            throw unsafe error!.takeRetainedValue() as any Error
        }
        return KeyReference(reference: key)
    }
}
