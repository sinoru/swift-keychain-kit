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

/// An item class whose value is a framework object rather than secret data: a key, a
/// certificate, or an identity.
public protocol ReferenceItemClass: ItemClass {
    /// The wrapper for the framework object items of this class are.
    associatedtype Reference: ItemReference
}

/// `kSecClassKey`
public enum CryptographicKey: ReferenceItemClass {
    public typealias Reference = KeyReference

    public static let secClass = kSecClassKey as String
}

/// `kSecClassCertificate`
public enum Certificate: ReferenceItemClass {
    public typealias Reference = CertificateReference

    public static let secClass = kSecClassCertificate as String
}

/// `kSecClassIdentity`
///
/// An identity is a certificate paired with its private key. It is not stored as an item of its
/// own: the keychain reports one wherever it holds both halves. The data protection keychain
/// reports the attributes of both; the file-based keychain on macOS reports only the
/// certificate's (measured on the iOS 27 simulator and macOS 26).
public enum Identity: ReferenceItemClass {
    public typealias Reference = IdentityReference

    public static let secClass = kSecClassIdentity as String
}
