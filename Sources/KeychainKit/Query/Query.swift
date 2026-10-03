//
//  Query.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// Search criteria for items of one class.
///
/// Every attribute set on the query must match exactly. How many items come back, and in what
/// form, is decided by the `Keychain` method the query is passed to rather than by the query.
public struct Query<Class: ItemClass>: Hashable, Sendable {
    /// The attributes an item must have.
    public var attributes: Attributes<Class>

    /// Which items to consider with respect to iCloud Keychain.
    ///
    /// This takes precedence over the `synchronizable` attribute key, because the framework's
    /// third option, `kSecAttrSynchronizableAny`, is not a boolean.
    public var synchronizable: SynchronizableMatch = .nonSynchronizableOnly

    /// Skip items that would prompt the user for authentication (`kSecUseAuthenticationUISkip`).
    ///
    /// Only meaningful for searches; the framework ignores it elsewhere.
    public var skipsItemsRequiringAuthentication = false

    /// Restrict the search to the item a persistent reference points at.
    public var persistentReference: PersistentReference?

    #if canImport(LocalAuthentication)
    /// The authentication context for items protected by an access control object.
    public var authenticationContext: AuthenticationContext?
    #endif

    /// A query for items with the given attributes; empty attributes match every item of the class.
    public init(_ attributes: Attributes<Class> = Attributes()) {
        self.attributes = attributes
    }

    /// Reads or writes one required attribute; the same as going through `attributes`.
    public subscript<Value>(key: AttributeKey<Class, Value>) -> Value? {
        get { attributes[key] }
        set { attributes[key] = newValue }
    }

    /// The dictionary for a `SecItem*` call, before any `kSecReturn*` or `kSecMatchLimit` key.
    package var secDictionary: SecDictionary {
        var dictionary = attributes.secDictionary
        dictionary[kSecClass as String] = .string(Class.secClass as String)
        switch synchronizable {
        case .nonSynchronizableOnly:
            // Absent is the framework's default and, on macOS, keeps the query off the
            // data protection keychain unless asked for otherwise.
            dictionary[kSecAttrSynchronizable as String] = nil
        case .synchronizableOnly:
            dictionary[kSecAttrSynchronizable as String] = .bool(true)
        case .any:
            dictionary[kSecAttrSynchronizable as String] = .string(kSecAttrSynchronizableAny as String)
        }
        if skipsItemsRequiringAuthentication {
            dictionary[kSecUseAuthenticationUI as String] = .string(kSecUseAuthenticationUISkip as String)
        }
        if let persistentReference {
            dictionary[kSecValuePersistentRef as String] = .data(persistentReference.rawValue)
        }
        #if canImport(LocalAuthentication)
        if let authenticationContext {
            dictionary[kSecUseAuthenticationContext as String] = authenticationContext.secValue
        }
        #endif
        return dictionary
    }
}

/// Which items a `Query` considers with respect to iCloud Keychain.
public enum SynchronizableMatch: Hashable, Sendable {
    /// Only items that do not sync. The framework's default.
    case nonSynchronizableOnly

    /// Only items that sync through iCloud Keychain.
    case synchronizableOnly

    /// Both kinds (`kSecAttrSynchronizableAny`).
    case any
}
