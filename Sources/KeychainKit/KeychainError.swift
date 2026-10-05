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

        /// An internal error occurred (`errSecInternalError`).
        ///
        /// An operation on a key also reports this for a failure that has no status of its
        /// own, such as an error in a domain the library does not know.
        public static let internalError = Code(rawValue: errSecInternalError)
    }
}

extension KeychainError {
    /// Turns a failing `OSStatus` into a thrown `KeychainError`.
    package static func check(_ status: OSStatus) throws(KeychainError) {
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }
    }

    /// Security reports failures in `NSOSStatusErrorDomain` with the status as the code.
    ///
    /// An operation on a key that lives on a token, the Secure Enclave included, reports the
    /// token's own error instead, in the LocalAuthentication or CryptoTokenKit domain. Those
    /// are classified the way the framework classifies them for the SecItem functions. What
    /// that leaves without a status of its own, an error in any other domain included, is an
    /// internal error. A missing error is reported as an invalid parameter.
    ///
    /// The domains are compared by name, which needs neither framework and so also works where
    /// LocalAuthentication is unavailable.
    init(cfError: CFError?) {
        guard let cfError else {
            self.init(code: .invalidParameter)
            return
        }
        let code = CFErrorGetCode(cfError)
        switch CFErrorGetDomain(cfError) as String? {
        case NSOSStatusErrorDomain:
            self.init(status: OSStatus(exactly: code) ?? Code.internalError.rawValue)
        case "com.apple.LocalAuthentication":
            self.init(code: Self.code(forLocalAuthenticationCode: code))
        case "CryptoTokenKit":
            self.init(code: Self.code(forCryptoTokenKitCode: code))
        default:
            self.init(code: .internalError)
        }
    }

    private static func code(forLocalAuthenticationCode code: CFIndex) -> Code {
        switch code {
        case -2: .userCanceled // LAErrorUserCancel
        case -1001: .invalidParameter // LAErrorParameter
        case -1004: .interactionNotAllowed // LAErrorNotInteractive
        default: .authenticationFailed
        }
    }

    private static func code(forCryptoTokenKitCode code: CFIndex) -> Code {
        switch code {
        case -8: .invalidParameter // TKErrorCodeBadParameter
        case -1: .unimplemented // TKErrorCodeNotImplemented
        case -4: .userCanceled // TKErrorCodeCanceledByUser
        case -3: .decodingFailed // TKErrorCodeCorruptedData
        case -6, -7: .itemNotFound // TKErrorCodeObjectNotFound, TKErrorCodeTokenNotFound
        default: .internalError
        }
    }
}

extension KeychainError: CustomStringConvertible {
    /// The framework's message for the status, followed by the status in parentheses.
    public var description: String {
        // The second argument is reserved and must always be nil.
        if let message = SecCopyErrorMessageString(status, nil) {
            return "\(message as String) (\(status))"
        }
        return "OSStatus \(status)"
    }
}

extension KeychainError: LocalizedError {
    public var errorDescription: String? {
        description
    }
}
