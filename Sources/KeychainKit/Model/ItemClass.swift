//
//  ItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Security

/// A keychain item class, corresponding to one value of `kSecClass`.
///
/// It serves as a type-level phantom tag so that only the attribute keys valid for a
/// class are exposed for it.
public protocol ItemClass {
    /// The constant to put under `kSecClass`.
    static var secClass: CFString { get }
}

/// `kSecClassGenericPassword`
public enum GenericPassword: ItemClass {
    public static var secClass: CFString { kSecClassGenericPassword }
}

/// `kSecClassInternetPassword`
public enum InternetPassword: ItemClass {
    public static var secClass: CFString { kSecClassInternetPassword }
}

/// `kSecClassCertificate`
public enum Certificate: ItemClass {
    public static var secClass: CFString { kSecClassCertificate }
}

/// `kSecClassKey`
public enum CryptographicKey: ItemClass {
    public static var secClass: CFString { kSecClassKey }
}

/// `kSecClassIdentity`
public enum Identity: ItemClass {
    public static var secClass: CFString { kSecClassIdentity }
}
