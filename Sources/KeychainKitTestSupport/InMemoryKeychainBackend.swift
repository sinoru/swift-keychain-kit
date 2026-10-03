//
//  InMemoryKeychainBackend.swift
//  KeychainKitTestSupport
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import SynchronizationKit

/// A test backend that mimics `SecItem*` semantics without touching a real keychain.
///
/// Primary-key collisions (`errSecDuplicateItem`), misses (`errSecItemNotFound`), and the result
/// shape for each combination of return keys are implemented in Phase 1 together with the
/// `KeychainBackend` protocol.
public final class InMemoryKeychainBackend: Sendable {
    /// One stored item. Its concrete shape is settled in Phase 1.
    struct StoredItem {}

    private struct State {
        var items: [StoredItem] = []
    }

    private let state = Mutex(State())

    public init() {}

    /// The number of items currently stored.
    public var itemCount: Int {
        state.withLock { $0.items.count }
    }
}
