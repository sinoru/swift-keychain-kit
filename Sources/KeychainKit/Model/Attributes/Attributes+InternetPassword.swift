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
        get { storage[Keys.server]?.string }
        set { storage[Keys.server] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrSecurityDomain`: the security domain. Part of the primary key.
    public var securityDomain: String? {
        get { storage[Keys.securityDomain]?.string }
        set { storage[Keys.securityDomain] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrPath`: the path component of the URL. Part of the primary key.
    public var path: String? {
        get { storage[Keys.path]?.string }
        set { storage[Keys.path] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrProtocol`: the network protocol. Part of the primary key.
    public var internetProtocol: InternetProtocol? {
        get { storage[Keys.internetProtocol]?.constant() }
        set { storage[Keys.internetProtocol] = newValue.map { SecValue(constant: $0) } }
    }

    /// `kSecAttrAuthenticationType`: the authentication scheme. Part of the primary key.
    public var authenticationType: AuthenticationType? {
        get { storage[Keys.authenticationType]?.constant() }
        set { storage[Keys.authenticationType] = newValue.map { SecValue(constant: $0) } }
    }

    /// `kSecAttrPort`: the port number. Part of the primary key.
    public var port: Int? {
        get { storage[Keys.port]?.int }
        set { storage[Keys.port] = newValue.map { .integer(Int64($0)) } }
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
