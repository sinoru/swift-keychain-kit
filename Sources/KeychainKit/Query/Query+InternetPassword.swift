//
//  Query+InternetPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

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
        self.server = server
        self.account = account
        self.internetProtocol = internetProtocol
        self.port = port
        self.path = path
    }
}

extension Query where Class == InternetPassword {
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
