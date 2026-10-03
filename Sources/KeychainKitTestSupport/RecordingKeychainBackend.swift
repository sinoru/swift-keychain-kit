//
//  RecordingKeychainBackend.swift
//  KeychainKitTestSupport
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import KeychainKit
internal import SynchronizationKit

/// A `KeychainBackend` that records every dictionary it receives and answers with a canned result.
///
/// For tests that check what a `Keychain` sends to the framework rather than what comes back.
public final class RecordingKeychainBackend: KeychainBackend, Sendable {
    /// One recorded call.
    package struct Call: Sendable {
        package enum Operation: Sendable {
            case add, copyMatching, update, delete
        }

        package let operation: Operation
        package let dictionary: SecDictionary
        /// The second dictionary of an `update`; `nil` otherwise.
        package let changes: SecDictionary?
    }

    private struct State: Sendable {
        var calls: [Call] = []
        var result: SecValue?
        var error: KeychainError?
    }

    private let state = Mutex(State())

    public init() {}

    /// Every call so far, oldest first.
    package var calls: [Call] {
        state.withLock { $0.calls }
    }

    /// The value returned from `add` and `copyMatching` until changed.
    package func respond(with result: SecValue?) {
        state.withLock {
            $0.result = result
            $0.error = nil
        }
    }

    /// The error thrown from every operation until changed.
    package func fail(with error: KeychainError) {
        state.withLock { $0.error = error }
    }

    // MARK: KeychainBackend

    @discardableResult
    package func add(_ attributes: SecDictionary) throws(KeychainError) -> SecValue? {
        try record(Call(operation: .add, dictionary: attributes, changes: nil))
    }

    package func copyMatching(_ query: SecDictionary) throws(KeychainError) -> SecValue? {
        try record(Call(operation: .copyMatching, dictionary: query, changes: nil))
    }

    package func update(_ query: SecDictionary, with attributes: SecDictionary) throws(KeychainError) {
        _ = try record(Call(operation: .update, dictionary: query, changes: attributes))
    }

    package func delete(_ query: SecDictionary) throws(KeychainError) {
        _ = try record(Call(operation: .delete, dictionary: query, changes: nil))
    }

    private func record(_ call: Call) throws(KeychainError) -> SecValue? {
        let outcome = state.withLock { state -> Result<SecValue?, KeychainError> in
            state.calls.append(call)
            if let error = state.error {
                return .failure(error)
            }
            return .success(state.result)
        }
        return try outcome.get()
    }
}
