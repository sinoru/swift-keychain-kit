//
//  AccessGroup.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// A keychain access group, the unit of sharing between apps of one team.
///
/// An item belongs to exactly one group. An app belongs to its app ID group, any keychain
/// access groups and app groups in its entitlements, and `token`. Naming a group the app does
/// not belong to fails with `errSecMissingEntitlement`, for searches as well as for adds.
public struct AccessGroup: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    /// Fails for the empty string, which the framework treats as an invalid group.
    public init?(rawValue: String) {
        guard !rawValue.isEmpty else {
            return nil
        }
        self.rawValue = rawValue
    }

    /// A keychain access group as Xcode names it: the team ID, a dot, and the group name.
    public static func keychainGroup(teamID: String, name: String) -> AccessGroup {
        precondition(!teamID.isEmpty && !name.isEmpty, "A keychain access group needs both a team ID and a name.")
        return AccessGroup(unchecked: "\(teamID).\(name)")
    }

    /// `kSecAttrAccessGroupToken`: the group for items on tokens such as smart cards, readable
    /// by every app that names it explicitly.
    public static let token = AccessGroup(unchecked: kSecAttrAccessGroupToken as String)

    private init(unchecked rawValue: String) {
        self.rawValue = rawValue
    }
}
