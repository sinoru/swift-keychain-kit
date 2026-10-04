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
    /// `CoreFoundationValue` asks it once and hands each branch the object as the type it
    /// established, which is bridged from there without the dynamic cast a conditional cast to
    /// the Swift type would run.
    init(cf value: AnyObject) {
        switch CoreFoundationValue(unchecked: value) {
        case .string(let string):
            self = .string(string as String)
        case .data(let data):
            self = .data(data as Data)
        case .boolean(let bool):
            self = .bool(bool)
        case .number(let number):
            // `NSNumber` bridges to `Int64` only when the value is exactly representable, so a
            // fraction or an integer beyond `Int64` is carried as an `object` rather than rounded.
            // `CFNumberGetValue` cannot stand in for this: it reports an unsigned value above
            // `Int64.max` as a successful conversion and hands back its bit pattern (measured on
            // macOS 26: `UInt64.max` reads as -1).
            if let integer = (number as NSNumber) as? Int64 {
                self = .integer(integer)
            } else {
                self = .object(SecObject(value))
            }
        case .date(let date):
            self = .date(date as Date)
        case .dictionary(let dictionary):
            if let dictionary = SecDictionary(cf: dictionary as NSDictionary) {
                self = .dictionary(dictionary)
            } else {
                self = .object(SecObject(value))
            }
        case .array(let array):
            let array = array as NSArray
            var values: [SecValue] = []
            values.reserveCapacity(array.count)
            for index in 0..<array.count {
                values.append(SecValue(cf: array.object(at: index) as AnyObject))
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
    ///
    /// Walks the `NSDictionary` directly. Casting to `[String: Any]` first would build a Swift
    /// dictionary only for this one to be built from it. The enumeration is marked `unsafe` for
    /// the block's stop pointer, which is written once, to end the walk at a key that is not a
    /// string, and not kept.
    init?(cf dictionary: NSDictionary) {
        var result = SecDictionary(minimumCapacity: dictionary.count)
        var hasOnlyStringKeys = true
        unsafe dictionary.enumerateKeysAndObjects { key, value, stop in
            guard let key = key as? NSString else {
                hasOnlyStringKeys = false
                unsafe stop.pointee = true
                return
            }
            result[SecItemKey(rawValue: key as String)] = SecValue(cf: value as AnyObject)
        }
        guard hasOnlyStringKeys else {
            return nil
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
