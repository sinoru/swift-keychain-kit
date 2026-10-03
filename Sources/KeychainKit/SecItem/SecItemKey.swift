//
//  SecItemKey.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

package import Foundation
internal import Security

/// A key in a SecItem dictionary, by the raw string of its `kSec*` constant.
///
/// A struct rather than an enum because the framework returns keys this library does not
/// declare, and `Attributes` has to carry those through. The keys the library uses are static
/// members below, so that a subscript reads `storage[.service]`.
///
/// Each static key is made from the `kSec*` constant, never from a string literal. A `String`
/// bridged from a constant `CFString` wraps that constant and bridges back to the same object
/// without allocating, while a `String` built in Swift allocates on every bridge once it is
/// longer than a tagged pointer holds (`"r_Attributes"`, `"v_PersistentRef"`).
package struct SecItemKey: RawRepresentable, Hashable, Sendable {
    package let rawValue: String

    package init(rawValue: String) {
        self.rawValue = rawValue
    }

    package init(_ constant: CFString) {
        rawValue = constant as String
    }
}

// MARK: - Item class and values

extension SecItemKey {
    package static let itemClass = SecItemKey(kSecClass)
    package static let valueData = SecItemKey(kSecValueData)
    package static let valueRef = SecItemKey(kSecValueRef)
    package static let valuePersistentRef = SecItemKey(kSecValuePersistentRef)
}

// MARK: - Attributes

extension SecItemKey {
    package static let accessible = SecItemKey(kSecAttrAccessible)
    package static let accessControl = SecItemKey(kSecAttrAccessControl)
    package static let accessGroup = SecItemKey(kSecAttrAccessGroup)
    package static let synchronizable = SecItemKey(kSecAttrSynchronizable)
    package static let creationDate = SecItemKey(kSecAttrCreationDate)
    package static let modificationDate = SecItemKey(kSecAttrModificationDate)
    package static let label = SecItemKey(kSecAttrLabel)

    package static let account = SecItemKey(kSecAttrAccount)
    package static let description = SecItemKey(kSecAttrDescription)
    package static let comment = SecItemKey(kSecAttrComment)
    package static let creator = SecItemKey(kSecAttrCreator)
    package static let type = SecItemKey(kSecAttrType)
    package static let isInvisible = SecItemKey(kSecAttrIsInvisible)
    package static let isNegative = SecItemKey(kSecAttrIsNegative)

    package static let service = SecItemKey(kSecAttrService)
    package static let generic = SecItemKey(kSecAttrGeneric)

    package static let server = SecItemKey(kSecAttrServer)
    package static let securityDomain = SecItemKey(kSecAttrSecurityDomain)
    package static let path = SecItemKey(kSecAttrPath)
    package static let internetProtocol = SecItemKey(kSecAttrProtocol)
    package static let authenticationType = SecItemKey(kSecAttrAuthenticationType)
    package static let port = SecItemKey(kSecAttrPort)
}

// MARK: - Search and call options

extension SecItemKey {
    package static let returnData = SecItemKey(kSecReturnData)
    package static let returnAttributes = SecItemKey(kSecReturnAttributes)
    package static let returnPersistentRef = SecItemKey(kSecReturnPersistentRef)
    package static let matchLimit = SecItemKey(kSecMatchLimit)
    package static let useDataProtectionKeychain = SecItemKey(kSecUseDataProtectionKeychain)
    package static let useAuthenticationUI = SecItemKey(kSecUseAuthenticationUI)
    #if canImport(LocalAuthentication) && !os(tvOS)
    package static let useAuthenticationContext = SecItemKey(kSecUseAuthenticationContext)
    #endif
    #if os(macOS)
    package static let useKeychain = SecItemKey(kSecUseKeychain)
    package static let matchSearchList = SecItemKey(kSecMatchSearchList)
    package static let matchItemList = SecItemKey(kSecMatchItemList)
    #endif
}
