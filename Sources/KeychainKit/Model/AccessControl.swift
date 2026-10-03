//
//  AccessControl.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// An access control object: an accessibility level plus the conditions a user must meet.
///
/// The `SecAccessControl` object is created eagerly in `init`, so an invalid accessibility value
/// is reported there rather than when the item is added. An `AccessControl` read back from the
/// keychain carries only the opaque object, because the framework does not expose the
/// constraints inside it; `accessibility` and `flags` are then `nil`.
public struct AccessControl: Hashable, Sendable {
    /// The accessibility level, or `nil` for a value read back from the keychain.
    public let accessibility: Accessibility?

    /// The user-presence conditions, or `nil` for a value read back from the keychain.
    public let flags: Flags?

    let secObject: SecObject

    /// Creates the access control object now, so an unknown accessibility value fails here.
    public init(accessibility: Accessibility, flags: Flags = []) throws(KeychainError) {
        self.accessibility = accessibility
        self.flags = flags
        self.secObject = try makeSecAccessControl(accessibility: accessibility, flags: flags)
    }

    init(opaque secObject: SecObject) {
        accessibility = nil
        flags = nil
        self.secObject = secObject
    }

    /// Values with known constraints compare by those constraints; opaque values compare by
    /// the contents of the underlying object, so reading the same item twice yields equal
    /// values. The two kinds never compare equal.
    public static func == (lhs: AccessControl, rhs: AccessControl) -> Bool {
        switch (lhs.flags, rhs.flags) {
        case (nil, nil):
            lhs.secObject.isEquivalent(to: rhs.secObject)
        case (.some, .some):
            lhs.accessibility == rhs.accessibility && lhs.flags == rhs.flags
        default:
            false
        }
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(accessibility)
        hasher.combine(flags)
    }
}

extension AccessControl {
    /// The conditions a user must satisfy, mirroring `SecAccessControlCreateFlags` bit for bit.
    public struct Flags: OptionSet, Hashable, Sendable {
        public let rawValue: UInt

        public init(rawValue: UInt) {
            self.rawValue = rawValue
        }

        /// Any form of user presence: biometrics, a passcode, or a paired companion device.
        public static let userPresence = Flags(rawValue: 1 << 0)

        /// Any enrolled biometric, surviving enrollment changes.
        public static let biometryAny = Flags(rawValue: 1 << 1)

        /// The biometrics enrolled at creation time; invalidated when enrollment changes.
        public static let biometryCurrentSet = Flags(rawValue: 1 << 3)

        /// The device passcode.
        public static let devicePasscode = Flags(rawValue: 1 << 4)

        /// A paired companion device such as an Apple Watch.
        @available(macOS 15.0, iOS 18.0, macCatalyst 18.0, *)
        @available(tvOS, unavailable)
        @available(watchOS, unavailable)
        @available(visionOS, unavailable)
        public static let companion = Flags(rawValue: 1 << 5)

        /// Combine the other constraints with logical OR instead of the default AND.
        public static let or = Flags(rawValue: 1 << 14)

        /// Combine the other constraints with logical AND explicitly.
        public static let and = Flags(rawValue: 1 << 15)

        /// The constraints apply to private key operations. Required for Secure Enclave keys.
        public static let privateKeyUsage = Flags(rawValue: 1 << 30)

        /// An application-specific password, prompted for on creation and on every use.
        public static let applicationPassword = Flags(rawValue: 1 << 31)
    }
}
