//
//  InternetProtocol.swift
//  KeychainKit
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

internal import Security

/// The network protocol of an internet password, one of the `kSecAttrProtocol*` constants.
public struct InternetProtocol: RawRepresentable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let ftp = InternetProtocol(kSecAttrProtocolFTP)
    public static let ftpAccount = InternetProtocol(kSecAttrProtocolFTPAccount)
    public static let http = InternetProtocol(kSecAttrProtocolHTTP)
    public static let irc = InternetProtocol(kSecAttrProtocolIRC)
    public static let nntp = InternetProtocol(kSecAttrProtocolNNTP)
    public static let pop3 = InternetProtocol(kSecAttrProtocolPOP3)
    public static let smtp = InternetProtocol(kSecAttrProtocolSMTP)
    public static let socks = InternetProtocol(kSecAttrProtocolSOCKS)
    public static let imap = InternetProtocol(kSecAttrProtocolIMAP)
    public static let ldap = InternetProtocol(kSecAttrProtocolLDAP)
    public static let appleTalk = InternetProtocol(kSecAttrProtocolAppleTalk)
    public static let afp = InternetProtocol(kSecAttrProtocolAFP)
    public static let telnet = InternetProtocol(kSecAttrProtocolTelnet)
    public static let ssh = InternetProtocol(kSecAttrProtocolSSH)
    public static let ftps = InternetProtocol(kSecAttrProtocolFTPS)
    public static let https = InternetProtocol(kSecAttrProtocolHTTPS)
    public static let httpProxy = InternetProtocol(kSecAttrProtocolHTTPProxy)
    public static let httpsProxy = InternetProtocol(kSecAttrProtocolHTTPSProxy)
    public static let ftpProxy = InternetProtocol(kSecAttrProtocolFTPProxy)
    public static let smb = InternetProtocol(kSecAttrProtocolSMB)
    public static let rtsp = InternetProtocol(kSecAttrProtocolRTSP)
    public static let rtspProxy = InternetProtocol(kSecAttrProtocolRTSPProxy)
    public static let daap = InternetProtocol(kSecAttrProtocolDAAP)
    public static let eppc = InternetProtocol(kSecAttrProtocolEPPC)
    public static let ipp = InternetProtocol(kSecAttrProtocolIPP)
    public static let nntps = InternetProtocol(kSecAttrProtocolNNTPS)
    public static let ldaps = InternetProtocol(kSecAttrProtocolLDAPS)
    public static let telnetS = InternetProtocol(kSecAttrProtocolTelnetS)
    public static let imaps = InternetProtocol(kSecAttrProtocolIMAPS)
    public static let ircs = InternetProtocol(kSecAttrProtocolIRCS)
    public static let pop3S = InternetProtocol(kSecAttrProtocolPOP3S)

    private init(_ constant: CFString) {
        rawValue = constant as String
    }
}
