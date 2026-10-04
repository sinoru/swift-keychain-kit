//
//  Item+ReferenceItemClass.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

extension Item where Class: ReferenceItemClass {
    /// The framework object the item is (`kSecValueRef`). `nil` on an item built by the caller
    /// without one; the read operations that return items always fill it in.
    public var reference: Class.Reference? {
        get {
            guard case .object(let object)? = value else {
                return nil
            }
            return Class.Reference(object.reference)
        }
        set { value = newValue.map { .object(SecObject($0.reference)) } }
    }

    /// An item with the given attributes and framework object.
    public init(attributes: Attributes<Class> = Attributes(), reference: Class.Reference?) {
        self.init(attributes: attributes)
        self.reference = reference
    }
}
