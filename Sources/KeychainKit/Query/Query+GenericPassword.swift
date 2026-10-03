//
//  Query+GenericPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Query where Class == GenericPassword {
    /// Generic passwords for `service`, narrowed to one `account` when given.
    public init(service: String, account: String? = nil) {
        self.init()
        self.service = service
        self.account = account
    }
}

extension Query where Class == GenericPassword {
    /// Forwards to `Attributes/service`.
    public var service: String? {
        get { attributes.service }
        set { attributes.service = newValue }
    }

    /// Forwards to `Attributes/generic`.
    public var generic: Data? {
        get { attributes.generic }
        set { attributes.generic = newValue }
    }
}
