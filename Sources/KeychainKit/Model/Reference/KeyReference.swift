//
//  KeyReference.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import CoreFoundationKit
internal import Foundation
public import Security

/// A reference to a cryptographic key (`SecKey`).
///
/// `SecKey` is an immutable Core Foundation object, which Core Foundation documents as safe to
/// query, retain, release, and pass between threads. That is why the conformance is unchecked.
public struct KeyReference: ItemReference, @unchecked Sendable {
    public let reference: SecKey

    public init(reference: SecKey) {
        self.reference = reference
    }

    public init?(_ object: AnyObject) {
        guard CoreFoundationValue.typeID(of: object) == SecKeyGetTypeID() else {
            return nil
        }
        // The type ID has established the type, so the forced cast cannot go wrong.
        self.init(reference: object as! SecKey)
    }
}
