//
//  TemporaryFileKeychain.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if os(macOS)
import Foundation
import Security

@testable import KeychainKit

/// A file-based keychain created in a temporary directory for the lifetime of a test.
///
/// Items added through `useKeychainEntry` and found through `searchListEntry` never reach the
/// login keychain, and `tearDown()` deletes the file. User interaction is disabled for the
/// process so that a misconfigured test fails with a status code instead of a dialog.
///
/// The file-based keychain is the legacy implementation on macOS (see TN3137), so these tests
/// exercise the SecItem plumbing, not data-protection semantics such as access groups.
/// `SecKeychainCreate` has been deprecated since macOS 12 but remains functional; this is the
/// only isolated keychain available to an unsigned test runner.
///
/// `SecKeychain` is an immutable handle to the keychain file, which is why passing it between
/// threads is safe and the conformance is unchecked.
final class TemporaryFileKeychain: @unchecked Sendable {
    /// Where the keychain file lives until `tearDown()`.
    let path: String

    private let keychain: SecKeychain

    #if compiler(>=6.4)
    @diagnose(DeprecatedDeclaration, as: ignored)
    #endif
    init() throws(KeychainError) {
        try KeychainError.check(SecKeychainSetUserInteractionAllowed(false))

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeychainKit-\(UUID().uuidString).keychain-db")
        let path = url.path
        let password = UUID().uuidString

        var reference: SecKeychain?
        let status = unsafe SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &reference)
        try KeychainError.check(status)
        guard let reference else {
            throw KeychainError(code: .notAvailable)
        }

        self.path = path
        self.keychain = reference
    }

    /// The storage handle for a `Keychain` that should target this keychain.
    var fileKeychain: FileKeychain {
        FileKeychain(reference: keychain)
    }

    /// The `kSecUseKeychain` entry that directs `SecItemAdd` at this keychain.
    var useKeychainEntry: SecDictionary {
        [.useKeychain: .object(SecObject(keychain))]
    }

    /// The `kSecMatchSearchList` entry that confines a query, update, or delete to this keychain.
    var searchListEntry: SecDictionary {
        [.matchSearchList: .array([.object(SecObject(keychain))])]
    }

    /// Deletes the keychain and its file.
    #if compiler(>=6.4)
    @diagnose(DeprecatedDeclaration, as: ignored)
    #endif
    func tearDown() throws(KeychainError) {
        try KeychainError.check(SecKeychainDelete(keychain))
    }
}
#endif
