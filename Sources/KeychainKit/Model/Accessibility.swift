//
//  Accessibility.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// When a keychain item can be read, relative to the device's lock state.
///
/// The `ThisDeviceOnly` values are restored only to the device that made the backup and are
/// incompatible with `synchronizable`. The deprecated `Always` values are intentionally absent.
/// Listed from most to least restrictive: `whenPasscodeSetThisDeviceOnly`, `whenUnlocked`,
/// `afterFirstUnlock`.
public struct Accessibility: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// Readable only while the device is unlocked. The default.
    public static let whenUnlocked = Accessibility(kSecAttrAccessibleWhenUnlocked)

    /// Readable after the first unlock following a restart, including from the background.
    public static let afterFirstUnlock = Accessibility(kSecAttrAccessibleAfterFirstUnlock)

    /// Readable only while unlocked, only on devices with a passcode, and never migrated.
    /// The item is deleted if the passcode is removed.
    public static let whenPasscodeSetThisDeviceOnly = Accessibility(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)

    /// `whenUnlocked`, never migrated to another device.
    public static let whenUnlockedThisDeviceOnly = Accessibility(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)

    /// `afterFirstUnlock`, never migrated to another device.
    public static let afterFirstUnlockThisDeviceOnly = Accessibility(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)

    /// Whether the item stays on the device that created it when a backup is restored elsewhere.
    public var isThisDeviceOnly: Bool {
        Self.thisDeviceOnlyValues.contains(self)
    }

    private static let thisDeviceOnlyValues: Set<Accessibility> = [
        .whenPasscodeSetThisDeviceOnly, .whenUnlockedThisDeviceOnly, .afterFirstUnlockThisDeviceOnly,
    ]

    private init(_ constant: CFString) {
        rawValue = constant as String
    }
}
