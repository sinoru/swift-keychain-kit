//
//  AttributeKey.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation
internal import Security

/// A typed key for one keychain item attribute.
///
/// The set of attributes is fixed by the Security framework, so the keys are predefined static
/// members and each one carries its own conversion to and from the dictionary representation.
/// That keeps `Attributes` type-safe without a public protocol for attribute values. The
/// `Class` parameter restricts a key to the item classes it is valid for: `.service` exists
/// only for `GenericPassword`, `.server` only for `InternetPassword`, and so on.
public struct AttributeKey<Class: ItemClass, Value: Sendable>: Hashable, Sendable {
    let rawKey: String
    let encode: @Sendable (Value) -> SecValue
    let decode: @Sendable (SecValue) -> Value?

    init(
        _ rawKey: CFString,
        encode: @escaping @Sendable (Value) -> SecValue,
        decode: @escaping @Sendable (SecValue) -> Value?,
    ) {
        self.rawKey = rawKey as String
        self.encode = encode
        self.decode = decode
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawKey == rhs.rawKey
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawKey)
    }
}

/// A typed key for an attribute the framework sets and the caller can only read.
public struct ReadOnlyAttributeKey<Class: ItemClass, Value: Sendable>: Hashable, Sendable {
    let rawKey: String
    let decode: @Sendable (SecValue) -> Value?

    init(_ rawKey: CFString, decode: @escaping @Sendable (SecValue) -> Value?) {
        self.rawKey = rawKey as String
        self.decode = decode
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawKey == rhs.rawKey
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawKey)
    }
}

/// The two password classes share most of their attributes.
public protocol PasswordItemClass: ItemClass {}

extension GenericPassword: PasswordItemClass {}
extension InternetPassword: PasswordItemClass {}

// MARK: - Codecs

/// Conversions between attribute value types and `SecValue`, shared by the key definitions.
enum AttributeCodec {
    static func encode(_ value: String) -> SecValue { .string(value) }
    static func decodeString(_ value: SecValue) -> String? {
        if case .string(let string) = value { string } else { nil }
    }

    static func encode(_ value: Data) -> SecValue { .data(value) }
    static func decodeData(_ value: SecValue) -> Data? {
        if case .data(let data) = value { data } else { nil }
    }

    static func encode(_ value: Bool) -> SecValue { .bool(value) }
    static func decodeBool(_ value: SecValue) -> Bool? {
        if case .bool(let bool) = value { bool } else { nil }
    }

    static func encode(_ value: Int) -> SecValue { .integer(Int64(value)) }
    static func decodeInt(_ value: SecValue) -> Int? {
        decodeInt64(value).flatMap { Int(exactly: $0) }
    }

    static func decodeInt64(_ value: SecValue) -> Int64? {
        if case .integer(let integer) = value { integer } else { nil }
    }

    /// `kSecAttrCreator` and `kSecAttrType` are four-character codes stored as numbers. They go
    /// through `Int64`, never `Int`, because a code with its top bit set exceeds `Int32.max` and
    /// `Int` is 32 bits on watchOS `arm64_32`.
    static func encode(_ value: UInt32) -> SecValue { .integer(Int64(value)) }
    static func decodeUInt32(_ value: SecValue) -> UInt32? {
        decodeInt64(value).flatMap { UInt32(exactly: $0) }
    }

    static func encode(_ value: Date) -> SecValue { .date(value) }
    static func decodeDate(_ value: SecValue) -> Date? {
        if case .date(let date) = value { date } else { nil }
    }

    static func encode<Raw: RawRepresentable>(_ value: Raw) -> SecValue where Raw.RawValue == String {
        .string(value.rawValue)
    }
    static func decodeRaw<Raw: RawRepresentable>(_ value: SecValue) -> Raw? where Raw.RawValue == String {
        decodeString(value).flatMap(Raw.init(rawValue:))
    }
}

// MARK: - Keys valid for every class

extension AttributeKey where Value == String {
    /// `kSecAttrLabel`: the user-visible label.
    public static var label: Self {
        AttributeKey(kSecAttrLabel, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }
}

extension AttributeKey where Value == AccessGroup {
    /// `kSecAttrAccessGroup`: the single access group the item belongs to.
    ///
    /// Omit it to use the app's default group. On macOS it applies only to the data
    /// protection keychain.
    public static var accessGroup: Self {
        AttributeKey(kSecAttrAccessGroup, encode: AttributeCodec.encode, decode: AttributeCodec.decodeRaw)
    }
}

extension AttributeKey where Value == Bool {
    /// `kSecAttrSynchronizable`: whether the item syncs through iCloud Keychain.
    ///
    /// Synchronizable items cannot use a `ThisDeviceOnly` accessibility. In a `Query`, the
    /// `synchronizable` property takes precedence over this key.
    public static var synchronizable: Self {
        AttributeKey(kSecAttrSynchronizable, encode: AttributeCodec.encode, decode: AttributeCodec.decodeBool)
    }
}

extension ReadOnlyAttributeKey where Value == Date {
    /// `kSecAttrCreationDate`: when the item was added.
    public static var creationDate: Self {
        ReadOnlyAttributeKey(kSecAttrCreationDate, decode: AttributeCodec.decodeDate)
    }

    /// `kSecAttrModificationDate`: when the item was last updated.
    public static var modificationDate: Self {
        ReadOnlyAttributeKey(kSecAttrModificationDate, decode: AttributeCodec.decodeDate)
    }
}

// MARK: - Keys shared by the password classes

extension AttributeKey where Class: PasswordItemClass, Value == String {
    /// `kSecAttrAccount`: the account name. Part of the primary key.
    public static var account: Self {
        AttributeKey(kSecAttrAccount, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }

    /// `kSecAttrDescription`: a user-visible description of the item.
    public static var description: Self {
        AttributeKey(kSecAttrDescription, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }

    /// `kSecAttrComment`: a user-editable comment.
    public static var comment: Self {
        AttributeKey(kSecAttrComment, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }
}

extension AttributeKey where Class: PasswordItemClass, Value == UInt32 {
    /// `kSecAttrCreator`: the creating application, as a four-character code.
    public static var creator: Self {
        AttributeKey(kSecAttrCreator, encode: AttributeCodec.encode, decode: AttributeCodec.decodeUInt32)
    }

    /// `kSecAttrType`: the item's type, as a four-character code.
    public static var type: Self {
        AttributeKey(kSecAttrType, encode: AttributeCodec.encode, decode: AttributeCodec.decodeUInt32)
    }
}

extension AttributeKey where Class: PasswordItemClass, Value == Bool {
    /// `kSecAttrIsInvisible`: hidden from keychain-browsing user interfaces.
    public static var isInvisible: Self {
        AttributeKey(kSecAttrIsInvisible, encode: AttributeCodec.encode, decode: AttributeCodec.decodeBool)
    }

    /// `kSecAttrIsNegative`: a placeholder whose password lives elsewhere.
    public static var isNegative: Self {
        AttributeKey(kSecAttrIsNegative, encode: AttributeCodec.encode, decode: AttributeCodec.decodeBool)
    }
}

// MARK: - Generic password keys

extension AttributeKey where Class == GenericPassword, Value == String {
    /// `kSecAttrService`: the service the password is for. Part of the primary key.
    public static var service: Self {
        AttributeKey(kSecAttrService, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }
}

extension AttributeKey where Class == GenericPassword, Value == Data {
    /// `kSecAttrGeneric`: arbitrary user-defined data that is not part of the primary key.
    public static var generic: Self {
        AttributeKey(kSecAttrGeneric, encode: AttributeCodec.encode, decode: AttributeCodec.decodeData)
    }
}

// MARK: - Internet password keys

extension AttributeKey where Class == InternetPassword, Value == String {
    /// `kSecAttrServer`: the server's domain name or IP address. Part of the primary key.
    public static var server: Self {
        AttributeKey(kSecAttrServer, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }

    /// `kSecAttrSecurityDomain`: the security domain. Part of the primary key.
    public static var securityDomain: Self {
        AttributeKey(kSecAttrSecurityDomain, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }

    /// `kSecAttrPath`: the path component of the URL. Part of the primary key.
    public static var path: Self {
        AttributeKey(kSecAttrPath, encode: AttributeCodec.encode, decode: AttributeCodec.decodeString)
    }
}

extension AttributeKey where Class == InternetPassword, Value == InternetProtocol {
    /// `kSecAttrProtocol`: the network protocol. Part of the primary key.
    public static var internetProtocol: Self {
        AttributeKey(kSecAttrProtocol, encode: AttributeCodec.encode, decode: AttributeCodec.decodeRaw)
    }
}

extension AttributeKey where Class == InternetPassword, Value == AuthenticationType {
    /// `kSecAttrAuthenticationType`: the authentication scheme. Part of the primary key.
    public static var authenticationType: Self {
        AttributeKey(kSecAttrAuthenticationType, encode: AttributeCodec.encode, decode: AttributeCodec.decodeRaw)
    }
}

extension AttributeKey where Class == InternetPassword, Value == Int {
    /// `kSecAttrPort`: the port number. Part of the primary key.
    public static var port: Self {
        AttributeKey(kSecAttrPort, encode: AttributeCodec.encode, decode: AttributeCodec.decodeInt)
    }
}
