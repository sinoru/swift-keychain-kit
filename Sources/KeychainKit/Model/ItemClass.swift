//
//  ItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// A keychain item class, corresponding to one value of `kSecClass`.
///
/// It serves as a type-level phantom tag so that only the attribute keys valid for a
/// class are exposed for it.
public protocol ItemClass {
    /// The raw string of the constant to put under `kSecClass`.
    ///
    /// A `String` rather than the `CFString` constant so that it is bridged once, not on
    /// every request.
    static var secClass: String { get }
}

/// `kSecClassGenericPassword`
public enum GenericPassword: ItemClass {
    public static let secClass = kSecClassGenericPassword as String
}

/// `kSecClassInternetPassword`
public enum InternetPassword: ItemClass {
    public static let secClass = kSecClassInternetPassword as String
}
