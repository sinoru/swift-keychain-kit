//
//  Item+GenericPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

extension Item where Class == GenericPassword {
    /// A generic password for `service` and `account` with raw secret data.
    public init(service: String, account: String, data: Data) {
        self.init(data: data)
        self.service = service
        self.account = account
    }

    /// A generic password for `service` and `account`, storing `password` as UTF-8.
    public init(service: String, account: String, password: String) {
        self.init(service: service, account: account, data: Data(password.utf8))
    }
}

extension Item where Class == GenericPassword {
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
