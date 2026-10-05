//
//  Protection.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

/// The two ways to restrict access to a keychain item.
///
/// `accessible` ties access to the device's lock state. `accessControl` adds user presence,
/// biometrics, a passcode, or an application password on top of an accessibility level.
public enum Protection: Hashable, Sendable {
    /// `kSecAttrAccessible`.
    case accessible(Accessibility)

    /// `kSecAttrAccessControl`.
    case accessControl(AccessControl)

    /// The accessibility level, whichever form carries it.
    ///
    /// An item read from the data protection keychain always reports an `accessControl`, even
    /// when it was stored as `accessible`, so this is how to inspect the level of a stored item.
    /// `nil` for an access control read back without a level.
    public var accessibility: Accessibility? {
        switch self {
        case .accessible(let accessibility): accessibility
        case .accessControl(let control): control.accessibility
        }
    }
}
