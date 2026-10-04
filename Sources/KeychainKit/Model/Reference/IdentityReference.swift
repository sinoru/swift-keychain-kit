//
//  IdentityReference.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Foundation
public import Security

/// A reference to an identity, a certificate paired with its private key (`SecIdentity`).
///
/// `SecIdentity` is an immutable Core Foundation object, which Core Foundation documents as safe to
/// query, retain, release, and pass between threads. That is why the conformance is unchecked.
public struct IdentityReference: ItemReference, @unchecked Sendable {
    public let reference: SecIdentity

    public init(reference: SecIdentity) {
        self.reference = reference
    }

    public init?(_ object: AnyObject) {
        guard Self.typeID(of: object) == SecIdentityGetTypeID() else {
            return nil
        }
        // The type ID has established the type, so the forced cast cannot go wrong.
        self.init(reference: object as! SecIdentity)
    }
}
