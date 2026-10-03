//
//  KeychainError.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

/// The error thrown when a Keychain Services call fails.
///
/// It preserves the original `OSStatus` and takes its human-readable message from
/// `SecCopyErrorMessageString`. `code` classifies the well-known values without closing
/// the door on codes this library does not name.
public struct KeychainError: Error, Sendable, Hashable {
    /// The status code the Security framework returned.
    public let status: OSStatus

    /// Wraps a status the framework returned.
    public init(status: OSStatus) {
        self.status = status
    }

    /// An error for one of the well-known codes.
    public init(code: Code) {
        self.status = code.rawValue
    }

    /// The well-known classification of `status`, if any.
    public var code: Code {
        Code(rawValue: status)
    }
}

extension KeychainError {
    /// A well-known `OSStatus` value.
    ///
    /// This is a struct rather than an enum so that a status the library does not name still
    /// round-trips through `rawValue` instead of being flattened into an "unknown" case.
    /// The constants below are the codes Apple documents for the SecItem functions, plus the
    /// general-purpose codes those functions are known to return.
    public struct Code: RawRepresentable, Hashable, Sendable {
        public let rawValue: OSStatus

        public init(rawValue: OSStatus) {
            self.rawValue = rawValue
        }

        /// An item with the same primary key already exists (`errSecDuplicateItem`).
        public static let duplicateItem = Code(rawValue: errSecDuplicateItem)

        /// No item matched the query (`errSecItemNotFound`).
        public static let itemNotFound = Code(rawValue: errSecItemNotFound)

        /// The caller lacks an entitlement the operation needs (`errSecMissingEntitlement`).
        ///
        /// Naming an access group the app does not belong to produces this code for both adds
        /// and searches, measured on the data protection keychain, even though Apple's
        /// documentation describes a search in such a group as returning `itemNotFound`.
        public static let missingEntitlement = Code(rawValue: errSecMissingEntitlement)

        /// The item is not accessible in the device's current lock state, or user interaction
        /// was required but not allowed (`errSecInteractionNotAllowed`).
        public static let interactionNotAllowed = Code(rawValue: errSecInteractionNotAllowed)

        /// Authentication failed (`errSecAuthFailed`).
        public static let authenticationFailed = Code(rawValue: errSecAuthFailed)

        /// The user canceled an authentication prompt (`errSecUserCanceled`).
        public static let userCanceled = Code(rawValue: errSecUserCanceled)

        /// One or more parameters were invalid (`errSecParam`).
        public static let invalidParameter = Code(rawValue: errSecParam)

        /// No keychain is available (`errSecNotAvailable`).
        public static let notAvailable = Code(rawValue: errSecNotAvailable)

        /// The data could not be decoded (`errSecDecode`).
        public static let decodingFailed = Code(rawValue: errSecDecode)

        /// The item is too large (`errSecDataTooLarge`).
        public static let dataTooLarge = Code(rawValue: errSecDataTooLarge)

        /// The keychain cannot be modified (`errSecReadOnly`).
        public static let readOnly = Code(rawValue: errSecReadOnly)

        /// The item reference is no longer valid (`errSecInvalidItemRef`).
        public static let invalidItemReference = Code(rawValue: errSecInvalidItemRef)

        /// The operation is not implemented (`errSecUnimplemented`).
        public static let unimplemented = Code(rawValue: errSecUnimplemented)

        /// Memory allocation failed (`errSecAllocate`).
        public static let allocationFailed = Code(rawValue: errSecAllocate)

        /// An I/O error occurred (`errSecIO`).
        public static let ioFailed = Code(rawValue: errSecIO)
    }
}

extension KeychainError: CustomStringConvertible {
    /// The framework's message for the status, followed by the status in parentheses.
    public var description: String {
        if let message = securityErrorMessage(for: status) {
            return "\(message) (\(status))"
        }
        return "OSStatus \(status)"
    }
}

extension KeychainError: LocalizedError {
    public var errorDescription: String? {
        description
    }
}
