//
//  Attributes+KeyItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

/// The classes that carry a key's attributes: a key itself, and an identity, whose attributes
/// are those of its certificate and its private key together.
public protocol KeyItemClass: ReferenceItemClass {}

extension CryptographicKey: KeyItemClass {}
extension Identity: KeyItemClass {}

extension Attributes where Class: KeyItemClass {
    /// `kSecAttrKeyClass`: whether the key is public, private, or symmetric. Set by the framework.
    public var keyClass: KeyClass? {
        storage[.keyClass]?.numericConstant()
    }

    /// `kSecAttrKeyType`: the algorithm of the key.
    public var keyType: KeyType? {
        get { storage[.keyType]?.numericConstant() }
        set { storage[.keyType] = newValue.map { SecValue(constant: $0) } }
    }

    /// `kSecAttrKeySizeInBits`: the number of bits in the key.
    public var keySizeInBits: Int? {
        get { storage[.keySizeInBits]?.int }
        set { storage[.keySizeInBits] = newValue.map { SecValue.integer(Int64($0)) } }
    }

    /// `kSecAttrEffectiveKeySize`: the effective number of bits in the key.
    public var effectiveKeySize: Int? {
        get { storage[.effectiveKeySize]?.int }
        set { storage[.effectiveKeySize] = newValue.map { SecValue.integer(Int64($0)) } }
    }

    /// `kSecAttrApplicationLabel`: the label used to look a key up programmatically. For a public or
    /// private key it is the hash of the public key.
    public var applicationLabel: Data? {
        get { storage[.applicationLabel]?.data }
        set { storage[.applicationLabel] = newValue.map(SecValue.data) }
    }

    /// `kSecAttrApplicationTag`: private tag data chosen by the application.
    public var applicationTag: Data? {
        get { storage[.applicationTag]?.data }
        set { storage[.applicationTag] = newValue.map(SecValue.data) }
    }

    /// `kSecAttrIsPermanent`: whether the key is stored in the keychain.
    public var isPermanent: Bool? {
        get { storage[.isPermanent]?.bool }
        set { storage[.isPermanent] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanEncrypt`: whether the key can encrypt data.
    public var canEncrypt: Bool? {
        get { storage[.canEncrypt]?.bool }
        set { storage[.canEncrypt] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanDecrypt`: whether the key can decrypt data.
    public var canDecrypt: Bool? {
        get { storage[.canDecrypt]?.bool }
        set { storage[.canDecrypt] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanDerive`: whether the key can derive another key.
    public var canDerive: Bool? {
        get { storage[.canDerive]?.bool }
        set { storage[.canDerive] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanSign`: whether the key can create a signature.
    public var canSign: Bool? {
        get { storage[.canSign]?.bool }
        set { storage[.canSign] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanVerify`: whether the key can verify a signature.
    public var canVerify: Bool? {
        get { storage[.canVerify]?.bool }
        set { storage[.canVerify] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanWrap`: whether the key can wrap another key.
    public var canWrap: Bool? {
        get { storage[.canWrap]?.bool }
        set { storage[.canWrap] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrCanUnwrap`: whether the key can unwrap another key.
    public var canUnwrap: Bool? {
        get { storage[.canUnwrap]?.bool }
        set { storage[.canUnwrap] = newValue.map(SecValue.bool) }
    }

    /// `kSecAttrTokenID`: the token that holds the key. Absent for a key in the keychain database.
    /// It cannot be changed once the key exists.
    public var tokenID: TokenID? {
        get { storage[.tokenID]?.constant() }
        set { storage[.tokenID] = newValue.map { SecValue(constant: $0) } }
    }
}
