//
//  SecValue.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import CoreFoundationKit
package import Foundation
internal import Security

/// One value in a SecItem dictionary, in Swift terms.
///
/// `SecItem*` take and return `CFDictionary`s whose values are a small closed set of CF
/// types. Modelling that set as an enum gives the rest of the library, and the test stores,
/// a `Sendable`, `Hashable` representation that never has to touch `CFTypeRef` or `Any`.
/// `kSec*` constants are `CFString`s and are stored as their raw string (`"svce"`, `"genp"`);
/// the Security framework accepts those strings in place of the constants.
package enum SecValue: Hashable, Sendable {
    /// A `CFString`, including any `kSec*` constant by its raw string.
    case string(String)
    /// A `CFData`.
    case data(Data)
    /// A `CFBoolean`.
    case bool(Bool)
    /// A `CFNumber`, widened to `Int64` so that the full range of a `UInt32` four-character
    /// code survives on 32-bit targets such as watchOS `arm64_32`, where `Int` is 32 bits.
    case integer(Int64)
    /// A `CFDate`.
    case date(Date)
    /// A `CFDictionary` with string keys, as returned for attributes.
    case dictionary(SecDictionary)
    /// A `CFArray`, as returned for `kSecMatchLimitAll`.
    case array([SecValue])
    /// Anything else, carried through untouched: `SecAccessControl`, `SecKey`,
    /// `SecKeychain`, `LAContext`, and so on.
    case object(SecObject)
}

/// A SecItem dictionary: `kSec*` keys as `SecItemKey`, values as `SecValue`.
package typealias SecDictionary = [SecItemKey: SecValue]

/// An opaque reference that passes through a SecItem dictionary.
///
/// The references that appear here are either immutable CF objects, which Core Foundation
/// documents as safe to query, retain, release, and pass between threads, or objects the caller
/// hands in for a single call (`LAContext`) that this library never mutates or retains beyond
/// that call. That is why the conformance is unchecked.
package struct SecObject: Hashable, @unchecked Sendable {
    package let reference: AnyObject

    package init(_ reference: AnyObject) {
        self.reference = reference
    }

    package static func == (lhs: SecObject, rhs: SecObject) -> Bool {
        lhs.reference === rhs.reference
    }

    package func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(reference))
    }

    /// Whether Core Foundation considers the two references equal (`CFEqual`), which holds for
    /// distinct objects with the same contents.
    ///
    /// Kept apart from `==` because `CFHash` does not follow it for every type: two equal
    /// `SecAccessControl` objects hash differently (measured on macOS 26).
    func isEquivalent(to other: SecObject) -> Bool {
        CFEqual(reference, other.reference)
    }
}

// MARK: - Core Foundation conversion

extension SecValue {
    /// Classifies a CF object by its type ID.
    ///
    /// The type ID is what tells the object apart because bridged casts are too permissive: a
    /// `CFBoolean` also casts to `Int`, and a `CFNumber` also casts to `Bool`.
    /// `CoreFoundationValue` asks it once and hands each branch what it established, which is
    /// bridged or walked from there without the dynamic cast a conditional cast to the Swift type
    /// would run.
    ///
    /// The object is one the framework returned, so it is read unchecked, and so is everything
    /// inside it.
    init(cf value: AnyObject) {
        self.init(CoreFoundationValue(unchecked: value))
    }

    /// Converts an object that has been told apart, and everything inside it.
    fileprivate init(_ value: CoreFoundationValue) {
        switch value {
        case .string(let string):
            self = .string(string as String)
        case .data(let data):
            self = .data(data as Data)
        case .boolean(let bool):
            self = .bool(bool)
        case .number(let number):
            // The keychain keeps an integer and a floating-point number apart: it stores a
            // `CFNumber` by asking `CFNumberIsFloatType`, and hands back a number of the type it
            // stored. Every numeric attribute modelled here is an integer, so only a number that
            // says it is one is read as one. A floating-point number, whole or not, and an
            // integer beyond `Int64` are carried as an `object` rather than rounded or truncated.
            //
            // `CoreFoundationValue.Number` asks the same question first, and reads an integer
            // without bridging it. A cast to `Int64` would take a floating-point `2.0` for an
            // integer, and `CFNumberGetValue` an unsigned value above `Int64.max` for a negative
            // one (measured on macOS 26: `UInt64.max` reads as -1).
            if case .integer(let integer)? = CoreFoundationValue.Number(number) {
                self = .integer(integer)
            } else {
                self = .object(SecObject(number.base))
            }
        case .date(let date):
            self = .date(date as Date)
        case .dictionary(let elements):
            if let dictionary = SecDictionary(elements) {
                self = .dictionary(dictionary)
            } else {
                self = .object(SecObject(elements.base))
            }
        case .array(let elements):
            var values: [SecValue] = []
            values.reserveCapacity(elements.count)
            for element in elements {
                values.append(SecValue(element))
            }
            self = .array(values)
        case .other(let object):
            self = .object(SecObject(object))
        }
    }

    /// The CF object to put in a SecItem dictionary.
    var cfValue: AnyObject {
        switch self {
        case .string(let string):
            string as CFString
        case .data(let data):
            data as CFData
        case .bool(let bool):
            bool ? kCFBooleanTrue : kCFBooleanFalse
        case .integer(let integer):
            integer as CFNumber
        case .date(let date):
            date as CFDate
        case .dictionary(let dictionary):
            dictionary.cfDictionary
        case .array(let array):
            array.map(\.cfValue) as CFArray
        case .object(let object):
            object.reference
        }
    }
}

extension SecDictionary {
    /// Converts a dictionary the framework returned, or `nil` when a key is not a string.
    init?(cf dictionary: NSDictionary) {
        guard case .dictionary(let elements) = CoreFoundationValue(unchecked: dictionary) else {
            return nil
        }
        self.init(elements)
    }

    /// Converts the keys and values of a dictionary, or `nil` when a key is not a string.
    ///
    /// The view hands over each key and value already told apart and builds no Swift dictionary
    /// on the way; casting to `[String: Any]` first would build one only for this one to be built
    /// from it. The walk ends at the first key that is not a string.
    fileprivate init?(_ elements: CoreFoundationValue.DictionaryView) {
        var result = SecDictionary(minimumCapacity: elements.count)
        for (key, value) in elements {
            guard case .string(let key) = key else {
                return nil
            }
            result[SecItemKey(rawValue: key as String)] = SecValue(value)
        }
        self = result
    }

    /// The `CFDictionary` to pass to a `SecItem*` function.
    ///
    /// Built as an `NSMutableDictionary` rather than bridged from a Swift dictionary. A bridged
    /// Swift dictionary converts the key of every lookup the framework makes back to a `String`,
    /// and filling the Core Foundation dictionary directly measured no slower than bridging.
    var cfDictionary: CFDictionary {
        let dictionary = NSMutableDictionary(capacity: count)
        for (key, value) in self {
            dictionary.setObject(value.cfValue, forKey: key.rawValue as NSString)
        }
        return dictionary
    }
}
