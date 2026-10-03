//
//  SecValue.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

package import Foundation
internal import Security

/// One value in a SecItem dictionary, in Swift terms.
///
/// `SecItem*` take and return `CFDictionary`s whose values are a small closed set of CF
/// types. Modelling that set as an enum gives the rest of the library, and the test backends,
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
    /// A `CFNumber` that fits in an `Int`, which every integer attribute does.
    case number(Int)
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

/// A SecItem dictionary: `kSec*` keys by their raw string, values as `SecValue`.
package typealias SecDictionary = [String: SecValue]

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
}

// MARK: - Core Foundation conversion

extension SecValue {
    /// Classifies a CF object by its type ID.
    ///
    /// The type ID check comes first because bridged casts are too permissive: a `CFBoolean`
    /// also casts to `Int`, and a `CFNumber` also casts to `Bool`.
    init(cf value: AnyObject) {
        switch CFGetTypeID(value) {
        case CFStringGetTypeID():
            if let string = value as? String {
                self = .string(string)
                return
            }
        case CFDataGetTypeID():
            if let data = value as? Data {
                self = .data(data)
                return
            }
        case CFBooleanGetTypeID():
            if let bool = value as? Bool {
                self = .bool(bool)
                return
            }
        case CFNumberGetTypeID():
            if let number = value as? Int {
                self = .number(number)
                return
            }
        case CFDateGetTypeID():
            if let date = value as? Date {
                self = .date(date)
                return
            }
        case CFDictionaryGetTypeID():
            if let dictionary = value as? [String: Any] {
                self = .dictionary(SecDictionary(cf: dictionary))
                return
            }
        case CFArrayGetTypeID():
            if let array = value as? [Any] {
                self = .array(array.map { SecValue(cf: $0 as AnyObject) })
                return
            }
        default:
            break
        }
        self = .object(SecObject(value))
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
        case .number(let number):
            number as CFNumber
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
    /// Converts a bridged dictionary, dropping entries whose keys are not strings.
    init(cf dictionary: [String: Any]) {
        self = dictionary.mapValues { SecValue(cf: $0 as AnyObject) }
    }

    /// The `CFDictionary` to pass to a `SecItem*` function.
    var cfDictionary: CFDictionary {
        mapValues(\.cfValue) as CFDictionary
    }
}
