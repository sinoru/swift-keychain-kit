//
//  Query+Passwords.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

extension Query where Class == GenericPassword {
    /// Generic passwords for `service`, narrowed to one `account` when given.
    public init(service: String, account: String? = nil) {
        self.init()
        self[.service] = service
        self[.account] = account
    }
}

extension Query where Class == InternetPassword {
    /// Internet passwords for `server`, narrowed by whichever other attributes are given.
    public init(
        server: String,
        account: String? = nil,
        internetProtocol: InternetProtocol? = nil,
        port: Int? = nil,
        path: String? = nil,
    ) {
        self.init()
        self[.server] = server
        self[.account] = account
        self[.internetProtocol] = internetProtocol
        self[.port] = port
        self[.path] = path
    }
}
