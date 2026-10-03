//
//  Attributes+InternetPassword.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

extension Attributes where Class == InternetPassword {
    /// `kSecAttrServer`: the server's domain name or IP address. Part of the primary key.
    public var server: String? {
        get { storage[.server]?.string }
        set { storage[.server] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrSecurityDomain`: the security domain. Part of the primary key.
    public var securityDomain: String? {
        get { storage[.securityDomain]?.string }
        set { storage[.securityDomain] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrPath`: the path component of the URL. Part of the primary key.
    public var path: String? {
        get { storage[.path]?.string }
        set { storage[.path] = newValue.map(SecValue.string) }
    }

    /// `kSecAttrProtocol`: the network protocol. Part of the primary key.
    public var internetProtocol: InternetProtocol? {
        get { storage[.internetProtocol]?.constant() }
        set { storage[.internetProtocol] = newValue.map { SecValue(constant: $0) } }
    }

    /// `kSecAttrAuthenticationType`: the authentication scheme. Part of the primary key.
    public var authenticationType: AuthenticationType? {
        get { storage[.authenticationType]?.constant() }
        set { storage[.authenticationType] = newValue.map { SecValue(constant: $0) } }
    }

    /// `kSecAttrPort`: the port number. Part of the primary key.
    public var port: Int? {
        get { storage[.port]?.int }
        set { storage[.port] = newValue.map { .integer(Int64($0)) } }
    }
}
