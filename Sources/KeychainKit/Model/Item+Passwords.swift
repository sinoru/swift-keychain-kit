//
//  Item+Passwords.swift
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
        self[.service] = service
        self[.account] = account
    }

    /// A generic password for `service` and `account`, storing `password` as UTF-8.
    public init(service: String, account: String, password: String) {
        self.init(service: service, account: account, data: Data(password.utf8))
    }
}

extension Item where Class == InternetPassword {
    /// An internet password for `account` at `server` with raw secret data.
    ///
    /// The optional parameters are the remaining primary-key attributes; leave out the ones
    /// that do not apply.
    public init(
        server: String,
        account: String,
        data: Data,
        internetProtocol: InternetProtocol? = nil,
        port: Int? = nil,
        path: String? = nil,
        authenticationType: AuthenticationType? = nil,
    ) {
        self.init(data: data)
        self[.server] = server
        self[.account] = account
        self[.internetProtocol] = internetProtocol
        self[.port] = port
        self[.path] = path
        self[.authenticationType] = authenticationType
    }

    /// An internet password for `account` at `server`, storing `password` as UTF-8.
    public init(
        server: String,
        account: String,
        password: String,
        internetProtocol: InternetProtocol? = nil,
        port: Int? = nil,
        path: String? = nil,
        authenticationType: AuthenticationType? = nil,
    ) {
        self.init(
            server: server,
            account: account,
            data: Data(password.utf8),
            internetProtocol: internetProtocol,
            port: port,
            path: path,
            authenticationType: authenticationType,
        )
    }
}

extension Item where Class: PasswordItemClass {
    /// The secret decoded as UTF-8.
    ///
    /// `nil` when there is no data or the data is not valid UTF-8. Setting it replaces `data`;
    /// setting `nil` clears it.
    public var password: String? {
        get { data.flatMap { String(data: $0, encoding: .utf8) } }
        set { data = newValue.map { Data($0.utf8) } }
    }
}
