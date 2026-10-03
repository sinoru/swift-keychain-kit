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
}
