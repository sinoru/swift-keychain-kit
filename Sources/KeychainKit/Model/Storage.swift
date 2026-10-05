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
/// older file-based keychain (see TN3137), and `SecItem` there reaches both unless told which,
/// so either case sets `kSecUseDataProtectionKeychain` on every call.
public enum Storage: Hashable, Sendable {
    /// The data protection keychain. Consistent across platforms, required for iCloud Keychain,
    /// biometrics, and the Secure Enclave, and Apple's recommendation on macOS. The default.
    case dataProtection

    #if os(macOS)
    /// The file-based keychain, for daemons and other code outside a user session, or for
    /// items that already live there. `nil` means the default keychain and default search list.
    ///
    /// Calls stay in this keychain and never reach the data protection keychain. Access groups
    /// and accessibility do not apply here and are ignored. What only the data protection
    /// keychain has fails with `invalidParameter`: an access control, a token such as the
    /// Secure Enclave, a synchronizable item, and the `token` access group.
    case fileBased(FileKeychain? = nil)
    #endif
}

extension Storage {
    /// Throws `invalidParameter` when a dictionary asks the file-based keychain for what only
    /// the data protection keychain has: an access control, a token, a synchronizable item, or
    /// the `token` access group.
    ///
    /// The framework would not refuse these. With `kSecUseDataProtectionKeychain` false it
    /// sends the call to the file-based keychain without looking further, and drops the
    /// entries that keychain has no place for (Security sources, `SecItemCategorizeQuery` and
    /// `SecItemCopyTranslatedAttributes`; measured on macOS 27). The item would be kept
    /// without the protection asked for. A private key's attributes in a key generation
    /// dictionary are validated the same way.
    package func validate(_ dictionary: SecDictionary) throws(KeychainError) {
        #if os(macOS)
        guard case .fileBased = self else {
            return
        }
        var levels = [dictionary]
        if case .dictionary(let privateKey)? = dictionary[.privateKeyAttrs] {
            levels.append(privateKey)
        }
        for entries in levels {
            guard entries[.accessControl] == nil,
                  entries[.tokenID] == nil,
                  entries[.synchronizable]?.bool != true,
                  entries[.accessGroup] != .string(AccessGroup.token.rawValue)
            else {
                throw KeychainError(code: .invalidParameter)
            }
        }
        #endif
    }
}

#if os(macOS)
/// A handle to one file-based keychain on macOS.
///
/// `SecKeychain` is an immutable handle to the keychain file, which is why it is safe to pass
/// between threads and the conformance is unchecked. Obtain one from the `SecKeychain*` API.
public struct FileKeychain: Hashable, @unchecked Sendable {
    /// The framework's handle.
    public let reference: SecKeychain

    /// Wraps a handle obtained from the `SecKeychain*` API.
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
