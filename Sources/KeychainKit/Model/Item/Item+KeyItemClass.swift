//
//  Item+KeyItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Item where Class: KeyItemClass {
    /// Forwards to `Attributes/keyClass`.
    public var keyClass: KeyClass? {
        attributes.keyClass
    }

    /// Forwards to `Attributes/keyType`.
    public var keyType: KeyType? {
        get { attributes.keyType }
        set { attributes.keyType = newValue }
    }

    /// Forwards to `Attributes/keySizeInBits`.
    public var keySizeInBits: Int? {
        get { attributes.keySizeInBits }
        set { attributes.keySizeInBits = newValue }
    }

    /// Forwards to `Attributes/effectiveKeySize`.
    public var effectiveKeySize: Int? {
        get { attributes.effectiveKeySize }
        set { attributes.effectiveKeySize = newValue }
    }

    /// Forwards to `Attributes/applicationLabel`.
    public var applicationLabel: Data? {
        get { attributes.applicationLabel }
        set { attributes.applicationLabel = newValue }
    }

    /// Forwards to `Attributes/applicationTag`.
    public var applicationTag: Data? {
        get { attributes.applicationTag }
        set { attributes.applicationTag = newValue }
    }

    /// Forwards to `Attributes/isPermanent`.
    public var isPermanent: Bool? {
        get { attributes.isPermanent }
        set { attributes.isPermanent = newValue }
    }

    /// Forwards to `Attributes/canEncrypt`.
    public var canEncrypt: Bool? {
        get { attributes.canEncrypt }
        set { attributes.canEncrypt = newValue }
    }

    /// Forwards to `Attributes/canDecrypt`.
    public var canDecrypt: Bool? {
        get { attributes.canDecrypt }
        set { attributes.canDecrypt = newValue }
    }

    /// Forwards to `Attributes/canDerive`.
    public var canDerive: Bool? {
        get { attributes.canDerive }
        set { attributes.canDerive = newValue }
    }

    /// Forwards to `Attributes/canSign`.
    public var canSign: Bool? {
        get { attributes.canSign }
        set { attributes.canSign = newValue }
    }

    /// Forwards to `Attributes/canVerify`.
    public var canVerify: Bool? {
        get { attributes.canVerify }
        set { attributes.canVerify = newValue }
    }

    /// Forwards to `Attributes/canWrap`.
    public var canWrap: Bool? {
        get { attributes.canWrap }
        set { attributes.canWrap = newValue }
    }

    /// Forwards to `Attributes/canUnwrap`.
    public var canUnwrap: Bool? {
        get { attributes.canUnwrap }
        set { attributes.canUnwrap = newValue }
    }

    /// Forwards to `Attributes/tokenID`.
    public var tokenID: TokenID? {
        get { attributes.tokenID }
        set { attributes.tokenID = newValue }
    }
}
