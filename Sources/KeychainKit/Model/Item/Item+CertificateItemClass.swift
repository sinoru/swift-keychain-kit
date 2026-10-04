//
//  Item+CertificateItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Item where Class: CertificateItemClass {
    /// Forwards to `Attributes/certificateType`.
    public var certificateType: CertificateType? {
        attributes.certificateType
    }

    /// Forwards to `Attributes/certificateEncoding`.
    public var certificateEncoding: CertificateEncoding? {
        attributes.certificateEncoding
    }

    /// Forwards to `Attributes/subject`.
    public var subject: Data? {
        attributes.subject
    }

    /// Forwards to `Attributes/issuer`.
    public var issuer: Data? {
        attributes.issuer
    }

    /// Forwards to `Attributes/serialNumber`.
    public var serialNumber: Data? {
        attributes.serialNumber
    }

    /// Forwards to `Attributes/subjectKeyID`.
    public var subjectKeyID: Data? {
        attributes.subjectKeyID
    }

    /// Forwards to `Attributes/publicKeyHash`.
    public var publicKeyHash: Data? {
        attributes.publicKeyHash
    }
}
