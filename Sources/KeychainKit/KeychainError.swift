//
//  KeychainError.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Security

/// The error thrown when a Keychain Services call fails.
///
/// It preserves the original `OSStatus` and takes its human-readable message from
/// `SecCopyErrorMessageString`. A classification of well-known codes (`Code`) arrives in Phase 1.
public struct KeychainError: Error, Sendable, Hashable {
    /// The status code the Security framework returned.
    public let status: OSStatus

    public init(status: OSStatus) {
        self.status = status
    }
}

extension KeychainError: CustomStringConvertible {
    public var description: String {
        if let message = securityErrorMessage(for: status) {
            return "\(message) (\(status))"
        }
        return "OSStatus \(status)"
    }
}
