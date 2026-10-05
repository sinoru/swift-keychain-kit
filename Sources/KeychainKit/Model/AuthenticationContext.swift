//
//  AuthenticationContext.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

#if canImport(LocalAuthentication) && !os(tvOS)
public import LocalAuthentication

/// An `LAContext` to use for `kSecUseAuthenticationContext`.
///
/// A pre-evaluated context lets a protected item be read without a second prompt, and the
/// context's `localizedReason` and `interactionNotAllowed` replace the deprecated
/// `kSecUseOperationPrompt` and `kSecUseAuthenticationUI` values.
///
/// Configure the context before handing it over and do not mutate it while a call is in
/// flight. The framework reads it once per call and this library never retains it past the
/// call, which is the basis for the unchecked `Sendable` conformance. Compares by identity.
///
/// On tvOS this is a type without values, so every `authenticationContext` parameter takes only
/// `nil` there. Its simulator SDK ships the framework, but `LAContext` itself is marked
/// unavailable, so `canImport` alone is not a sufficient guard.
public struct AuthenticationContext: Hashable, @unchecked Sendable {
    /// The wrapped context.
    public let context: LAContext

    /// Wraps a context the caller has configured.
    public init(_ context: LAContext) {
        self.context = context
    }

    public static func == (lhs: AuthenticationContext, rhs: AuthenticationContext) -> Bool {
        lhs.context === rhs.context
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(context))
    }

    var secValue: SecValue {
        .object(SecObject(context))
    }

    /// Puts the context into the dictionary for a `SecItem*` or `SecKey*` call.
    func apply(to dictionary: inout SecDictionary) {
        dictionary[.useAuthenticationContext] = secValue
    }
}
#else
/// The stand-in for an `LAContext` wrapper where `LAContext` is unavailable.
///
/// It has no cases, so no value of it can be made and every `authenticationContext` parameter
/// takes only `nil`. It exists so that each operation has one signature on every platform.
public enum AuthenticationContext: Hashable, Sendable {
    func apply(to dictionary: inout SecDictionary) {
        switch self {}
    }
}
#endif
