//
//  Attributes+InternetPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

extension Attributes where Class == InternetPassword {
    /// `kSecAttrServer`: the server's domain name or IP address. Part of the primary key.
    public var server: String? {
        get { value(Keys.server, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.server) }
    }

    /// `kSecAttrSecurityDomain`: the security domain. Part of the primary key.
    public var securityDomain: String? {
        get { value(Keys.securityDomain, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.securityDomain) }
    }

    /// `kSecAttrPath`: the path component of the URL. Part of the primary key.
    public var path: String? {
        get { value(Keys.path, as: \.string) }
        set { setValue(newValue.map(SecValue.string), for: Keys.path) }
    }

    /// `kSecAttrProtocol`: the network protocol. Part of the primary key.
    public var internetProtocol: InternetProtocol? {
        get { value(Keys.internetProtocol, as: { $0.constant() }) }
        set { setValue(newValue.map { SecValue(constant: $0) }, for: Keys.internetProtocol) }
    }

    /// `kSecAttrAuthenticationType`: the authentication scheme. Part of the primary key.
    public var authenticationType: AuthenticationType? {
        get { value(Keys.authenticationType, as: { $0.constant() }) }
        set { setValue(newValue.map { SecValue(constant: $0) }, for: Keys.authenticationType) }
    }

    /// `kSecAttrPort`: the port number. Part of the primary key.
    public var port: Int? {
        get { value(Keys.port, as: \.int) }
        set { setValue(newValue.map { .integer(Int64($0)) }, for: Keys.port) }
    }
}

/// File-scoped because a type nested in a generic struct cannot hold static stored properties.
private enum Keys {
    static let server = kSecAttrServer as String
    static let securityDomain = kSecAttrSecurityDomain as String
    static let path = kSecAttrPath as String
    static let internetProtocol = kSecAttrProtocol as String
    static let authenticationType = kSecAttrAuthenticationType as String
    static let port = kSecAttrPort as String
}
