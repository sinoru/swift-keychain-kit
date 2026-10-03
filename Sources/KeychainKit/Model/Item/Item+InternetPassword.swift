//
//  Item+InternetPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

public import Foundation

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
        self.server = server
        self.account = account
        self.internetProtocol = internetProtocol
        self.port = port
        self.path = path
        self.authenticationType = authenticationType
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

extension Item where Class == InternetPassword {
    /// Forwards to `Attributes/server`.
    public var server: String? {
        get { attributes.server }
        set { attributes.server = newValue }
    }

    /// Forwards to `Attributes/securityDomain`.
    public var securityDomain: String? {
        get { attributes.securityDomain }
        set { attributes.securityDomain = newValue }
    }

    /// Forwards to `Attributes/path`.
    public var path: String? {
        get { attributes.path }
        set { attributes.path = newValue }
    }

    /// Forwards to `Attributes/internetProtocol`.
    public var internetProtocol: InternetProtocol? {
        get { attributes.internetProtocol }
        set { attributes.internetProtocol = newValue }
    }

    /// Forwards to `Attributes/authenticationType`.
    public var authenticationType: AuthenticationType? {
        get { attributes.authenticationType }
        set { attributes.authenticationType = newValue }
    }

    /// Forwards to `Attributes/port`.
    public var port: Int? {
        get { attributes.port }
        set { attributes.port = newValue }
    }
}
