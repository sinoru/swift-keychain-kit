//
//  SecurityStatus.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Foundation
internal import Security

/// Returns the description that `SecCopyErrorMessageString` provides for a status code.
///
/// The Bridge folder is the only place that calls the Security framework's C API directly.
/// No `unsafe` marker leaks out of this folder.
func securityErrorMessage(for status: OSStatus) -> String? {
    // The second argument is reserved and must always be nil.
    guard let message = SecCopyErrorMessageString(status, nil) else {
        return nil
    }
    return message as String
}
