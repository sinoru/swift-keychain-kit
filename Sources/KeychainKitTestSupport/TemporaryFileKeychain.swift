//
//  TemporaryFileKeychain.swift
//  KeychainKitTestSupport
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
internal import Foundation
public import KeychainKit
internal import Security

/// A file-based keychain created in a temporary directory for the lifetime of a test.
///
/// Items added through `useKeychainEntry` and found through `searchListEntry` never reach the
/// login keychain, and `tearDown()` deletes the file. User interaction is disabled for the
/// process so that a misconfigured test fails with a status code instead of a dialog.
///
/// The file-based keychain is the legacy implementation on macOS (see TN3137), so these tests
/// exercise the Bridge plumbing, not data-protection semantics such as access groups.
/// `SecKeychainCreate` has been deprecated since macOS 12 but remains functional; this is the
/// only isolated keychain available to an unsigned test runner.
///
/// `SecKeychain` is an immutable handle to the keychain file, which is why passing it between
/// threads is safe and the conformance is unchecked.
public final class TemporaryFileKeychain: @unchecked Sendable {
    /// Where the keychain file lives until `tearDown()`.
    public let path: String

    private let keychain: SecKeychain

    @diagnose(DeprecatedDeclaration, as: ignored)
    public init() throws(KeychainError) {
        try Self.check(SecKeychainSetUserInteractionAllowed(false))

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeychainKit-\(UUID().uuidString).keychain-db")
        let path = url.path
        let password = UUID().uuidString

        var reference: SecKeychain?
        let status = password.withCString { passwordPointer in
            unsafe SecKeychainCreate(path, UInt32(password.utf8.count), passwordPointer, false, nil, &reference)
        }
        try Self.check(status)
        guard let reference else {
            throw KeychainError(code: .notAvailable)
        }

        self.path = path
        self.keychain = reference
    }

    /// The storage handle for a `Keychain` that should target this keychain.
    public var fileKeychain: FileKeychain {
        FileKeychain(reference: keychain)
    }

    /// The `kSecUseKeychain` entry that directs `SecItemAdd` at this keychain.
    package var useKeychainEntry: SecDictionary {
        [kSecUseKeychain as String: .object(SecObject(keychain))]
    }

    /// The `kSecMatchSearchList` entry that confines a query, update, or delete to this keychain.
    package var searchListEntry: SecDictionary {
        [kSecMatchSearchList as String: .array([.object(SecObject(keychain))])]
    }

    /// Deletes the keychain and its file.
    @diagnose(DeprecatedDeclaration, as: ignored)
    public func tearDown() throws(KeychainError) {
        try Self.check(SecKeychainDelete(keychain))
    }

    private static func check(_ status: OSStatus) throws(KeychainError) {
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }
    }
}
#endif
