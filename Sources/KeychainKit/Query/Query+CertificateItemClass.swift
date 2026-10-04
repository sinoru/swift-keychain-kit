//
//  Query+CertificateItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

// A certificate's attributes are read-only on an item because the framework derives them, but
// they are valid match criteria, so a query can set them.

extension Query where Class: CertificateItemClass {
    /// Matches on `Attributes/certificateType`, which is read-only on an item.
    public var certificateType: CertificateType? {
        get { attributes.certificateType }
        set { attributes.storage[.certificateType] = newValue.map { SecValue.integer(Int64($0.rawValue)) } }
    }

    /// Matches on `Attributes/certificateEncoding`, which is read-only on an item.
    public var certificateEncoding: CertificateEncoding? {
        get { attributes.certificateEncoding }
        set { attributes.storage[.certificateEncoding] = newValue.map { SecValue.integer(Int64($0.rawValue)) } }
    }

    /// Matches on `Attributes/subject`, which is read-only on an item.
    public var subject: Data? {
        get { attributes.subject }
        set { attributes.storage[.subject] = newValue.map(SecValue.data) }
    }

    /// Matches on `Attributes/issuer`, which is read-only on an item.
    public var issuer: Data? {
        get { attributes.issuer }
        set { attributes.storage[.issuer] = newValue.map(SecValue.data) }
    }

    /// Matches on `Attributes/serialNumber`, which is read-only on an item.
    public var serialNumber: Data? {
        get { attributes.serialNumber }
        set { attributes.storage[.serialNumber] = newValue.map(SecValue.data) }
    }

    /// Matches on `Attributes/subjectKeyID`, which is read-only on an item.
    public var subjectKeyID: Data? {
        get { attributes.subjectKeyID }
        set { attributes.storage[.subjectKeyID] = newValue.map(SecValue.data) }
    }

    /// Matches on `Attributes/publicKeyHash`, which is read-only on an item.
    public var publicKeyHash: Data? {
        get { attributes.publicKeyHash }
        set { attributes.storage[.publicKeyHash] = newValue.map(SecValue.data) }
    }
}
