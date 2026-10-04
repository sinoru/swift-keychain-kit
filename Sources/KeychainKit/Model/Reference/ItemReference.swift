//
//  ItemReference.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// A reference to a keychain item that is a framework object: a key, a certificate, or an
/// identity.
///
/// Unlike a `PersistentReference` it is valid only inside the process that obtained it, and it
/// is what the Security framework's own functions take.
///
/// Two references are equal when they wrap the same object. Core Foundation's own comparison is
/// not used because it is not a sound basis for `Hashable`: two `SecKey` objects holding the
/// same key compare equal under `CFEqual` yet hash differently under `CFHash`, and a generated
/// key does not compare equal to the same key imported from its external representation
/// (measured on macOS 26).
public protocol ItemReference: Hashable, Sendable {
    /// The Security framework type the reference wraps.
    associatedtype Object: AnyObject

    /// The framework's object.
    var reference: Object { get }

    /// Wraps an object obtained from the Security framework.
    init(reference: Object)

    /// Wraps `object` when it is of the wrapped type, judged by its Core Foundation type ID.
    ///
    /// A cast cannot make this judgement. Core Foundation objects of unrelated types share one
    /// Objective-C class, so a cast to a Core Foundation type succeeds for any of them: casting a
    /// `SecAccessControl` or a `CFString` to `SecKey` yields a value (measured on macOS 26).
    ///
    /// An object that cannot be asked for a type ID at all, a proxy, is turned away as well
    /// rather than sent a message it would raise on (measured on macOS 26 with an
    /// `NSProtocolChecker`).
    init?(_ object: AnyObject)
}

extension ItemReference {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.reference === rhs.reference
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(reference))
    }
}
