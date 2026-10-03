//
//  SecValue+Values.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

package import Foundation

/// Typed views of a `SecValue`, each `nil` when the value is of another kind.
extension SecValue {
    package var string: String? {
        if case .string(let value) = self { value } else { nil }
    }

    package var data: Data? {
        if case .data(let value) = self { value } else { nil }
    }

    package var integer: Int64? {
        if case .integer(let value) = self { value } else { nil }
    }

    package var date: Date? {
        if case .date(let value) = self { value } else { nil }
    }

    /// The file-based keychain returns boolean attributes as `CFBoolean`. The data protection
    /// keychain is reported to return some of them, such as `kSecAttrSynchronizable`, as a
    /// `CFNumber` holding 0 or 1; that cannot be verified from an unsigned test runner, so both
    /// forms are accepted. Any other integer is not a boolean and reads as `nil`.
    package var bool: Bool? {
        switch self {
        case .bool(let value):
            value
        case .integer(0):
            false
        case .integer(1):
            true
        default:
            nil
        }
    }

    /// `integer` narrowed to `Int`, or `nil` where it does not fit: `Int` is 32 bits on watchOS `arm64_32`.
    package var int: Int? {
        integer.flatMap { Int(exactly: $0) }
    }

    /// A four-character code (`kSecAttrCreator`, `kSecAttrType`). It travels as `Int64`, never
    /// `Int`, because a code with its top bit set exceeds `Int32.max`.
    package var fourCharacterCode: UInt32? {
        integer.flatMap { UInt32(exactly: $0) }
    }

    package init(fourCharacterCode: UInt32) {
        self = .integer(Int64(fourCharacterCode))
    }

    /// A `kSec*` constant stored by its raw string, read back through the type's `RawRepresentable` init.
    package func constant<Constant: RawRepresentable>() -> Constant? where Constant.RawValue == String {
        string.flatMap(Constant.init(rawValue:))
    }

    package init<Constant: RawRepresentable>(constant: Constant) where Constant.RawValue == String {
        self = .string(constant.rawValue)
    }
}
