//
//  Storage.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
public import Security
#endif

/// Which keychain implementation a `Keychain` talks to.
///
/// iOS, tvOS, watchOS, and visionOS have only the data protection keychain. macOS also has the
/// older file-based keychain (see TN3137), which `SecItem` targets by default there unless
/// told otherwise, so `dataProtection` sets `kSecUseDataProtectionKeychain` on every call.
public enum Storage: Hashable, Sendable {
    /// The data protection keychain. Consistent across platforms, required for iCloud Keychain,
    /// biometrics, and the Secure Enclave, and Apple's recommendation on macOS. The default.
    case dataProtection

    #if os(macOS)
    /// The file-based keychain, for daemons and other code outside a user session, or for
    /// items that already live there. `nil` means the default keychain and default search list.
    ///
    /// Access groups, accessibility, and access control do not apply here.
    case fileBased(FileKeychain? = nil)
    #endif
}

#if os(macOS)
/// A handle to one file-based keychain on macOS.
///
/// `SecKeychain` is an immutable handle to the keychain file, which is why it is safe to pass
/// between threads and the conformance is unchecked. Obtain one from the `SecKeychain*` API.
public struct FileKeychain: Hashable, @unchecked Sendable {
    public let reference: SecKeychain

    public init(reference: SecKeychain) {
        self.reference = reference
    }

    public static func == (lhs: FileKeychain, rhs: FileKeychain) -> Bool {
        lhs.reference === rhs.reference
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(reference))
    }
}
#endif
