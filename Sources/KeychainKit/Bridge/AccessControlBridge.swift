//
//  AccessControlBridge.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Foundation
internal import Security

/// Creates the `SecAccessControl` object for an accessibility level and flags.
///
/// The framework rejects an unknown accessibility value with `errSecParam`; any flag
/// combination is accepted at creation and judged when the item is used.
func makeSecAccessControl(accessibility: Accessibility, flags: AccessControl.Flags) throws(KeychainError) -> SecObject {
    var error: Unmanaged<CFError>?
    let control = unsafe SecAccessControlCreateWithFlags(
        nil,
        accessibility.rawValue as CFString,
        SecAccessControlCreateFlags(rawValue: flags.rawValue),
        &error,
    )
    guard let control else {
        throw KeychainError(cfError: unsafe error?.takeRetainedValue())
    }
    return SecObject(control)
}

extension KeychainError {
    /// Security reports failures in `NSOSStatusErrorDomain` with the status as the code.
    /// Anything else, including a missing error, is reported as an invalid parameter.
    init(cfError: CFError?) {
        guard let cfError else {
            self.init(code: .invalidParameter)
            return
        }
        let error = cfError as any Error as NSError
        if error.domain == NSOSStatusErrorDomain {
            self.init(status: OSStatus(error.code))
        } else {
            self.init(code: .invalidParameter)
        }
    }
}
