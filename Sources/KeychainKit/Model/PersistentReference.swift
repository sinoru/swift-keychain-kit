//
//  PersistentReference.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

/// An opaque, storable handle to one keychain item (`kSecValuePersistentRef`).
///
/// Unlike an item reference it survives the process, so it can be written to disk and used to
/// find the same item later. Apple advises against persistent references to synchronizable
/// items, which may not resolve after the item changes on another device.
public struct PersistentReference: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }
}
