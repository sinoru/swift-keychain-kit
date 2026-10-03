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
/// Every writable attribute of `attributes` is reachable directly on the query, so
/// `query.service` and `query.attributes.service` are the same thing.
public struct Query<Class: ItemClass>: Hashable, Sendable {
    /// The attributes an item must have.
    public var attributes: Attributes<Class>

    /// Which items to consider with respect to iCloud Keychain.
    ///
    /// This takes precedence over the `synchronizable` attribute, because the framework's third
    /// option, `kSecAttrSynchronizableAny`, is not a boolean.
    public var synchronizable: SynchronizableMatch = .nonSynchronizableOnly

    /// Skip items that would prompt the user for authentication (`kSecUseAuthenticationUISkip`).
    ///
    /// Applies to searches only. The framework accepts the option solely for
    /// `SecItemCopyMatching` and rejects an update or delete that carries it with `errSecParam`,
    /// so the library leaves it out of those two calls.
    public var skipsItemsRequiringAuthentication = false

    /// Restrict the search to the item a persistent reference points at.
    public var persistentReference: PersistentReference?

    #if canImport(LocalAuthentication) && !os(tvOS)
    /// The authentication context for items protected by an access control object.
    public var authenticationContext: AuthenticationContext?
    #endif

    /// A query for items with the given attributes; empty attributes match every item of the class.
    public init(_ attributes: Attributes<Class> = Attributes()) {
        self.attributes = attributes
    }

    /// The dictionary for a `SecItem*` call, before any `kSecReturn*`, `kSecMatchLimit`, or
    /// search-only key.
    package var secDictionary: SecDictionary {
        var dictionary = attributes.secDictionary
        dictionary[Keys.itemClass] = .string(Class.secClass)
        switch synchronizable {
        case .nonSynchronizableOnly:
            // Absent is the framework's default and, on macOS, keeps the query off the
            // data protection keychain unless asked for otherwise.
            dictionary[Keys.synchronizable] = nil
        case .synchronizableOnly:
            dictionary[Keys.synchronizable] = .bool(true)
        case .any:
            dictionary[Keys.synchronizable] = .string(Keys.synchronizableAny)
        }
        if let persistentReference {
            dictionary[Keys.valuePersistentRef] = .data(persistentReference.rawValue)
        }
        #if canImport(LocalAuthentication) && !os(tvOS)
        if let authenticationContext {
            dictionary[Keys.useAuthenticationContext] = authenticationContext.secValue
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

/// File-scoped because a type nested in a generic struct cannot hold static stored properties.
private enum Keys {
    static let itemClass = kSecClass as String
    static let synchronizable = kSecAttrSynchronizable as String
    static let synchronizableAny = kSecAttrSynchronizableAny as String
    static let valuePersistentRef = kSecValuePersistentRef as String
    #if canImport(LocalAuthentication) && !os(tvOS)
    static let useAuthenticationContext = kSecUseAuthenticationContext as String
    #endif
}
