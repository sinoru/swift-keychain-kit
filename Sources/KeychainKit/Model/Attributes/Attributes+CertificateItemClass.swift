//
//  Attributes+CertificateItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

/// The classes that carry a certificate's attributes: a certificate itself, and an identity,
/// whose attributes are those of its certificate and its private key together.
public protocol CertificateItemClass: ReferenceItemClass {}

extension Certificate: CertificateItemClass {}
extension Identity: CertificateItemClass {}

// The framework derives every one of these from the certificate, so none can be set.

extension Attributes where Class: CertificateItemClass {
    /// `kSecAttrCertificateType`: the type of the certificate. Set by the framework.
    public var certificateType: CertificateType? {
        storage[.certificateType]?.uint32.map(CertificateType.init(rawValue:))
    }

    /// `kSecAttrCertificateEncoding`: the encoding of the certificate. Set by the framework.
    public var certificateEncoding: CertificateEncoding? {
        storage[.certificateEncoding]?.uint32.map(CertificateEncoding.init(rawValue:))
    }

    /// `kSecAttrSubject`: the X.500 subject name. Set by the framework.
    public var subject: Data? {
        storage[.subject]?.data
    }

    /// `kSecAttrIssuer`: the X.500 issuer name. Set by the framework.
    public var issuer: Data? {
        storage[.issuer]?.data
    }

    /// `kSecAttrSerialNumber`: the serial number. Set by the framework.
    public var serialNumber: Data? {
        storage[.serialNumber]?.data
    }

    /// `kSecAttrSubjectKeyID`: the subject key identifier. Set by the framework.
    public var subjectKeyID: Data? {
        storage[.subjectKeyID]?.data
    }

    /// `kSecAttrPublicKeyHash`: the hash of the certificate's public key. Set by the framework.
    public var publicKeyHash: Data? {
        storage[.publicKeyHash]?.data
    }
}
