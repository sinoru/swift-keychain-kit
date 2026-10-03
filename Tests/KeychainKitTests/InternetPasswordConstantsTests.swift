//
//  InternetPasswordConstantsTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Security
import Testing

@testable import KeychainKit

@Suite struct InternetPasswordConstantsTests {
    @Test(arguments: [
        (InternetProtocol.ftp, kSecAttrProtocolFTP as String), (.ftpAccount, kSecAttrProtocolFTPAccount as String),
        (.http, kSecAttrProtocolHTTP as String), (.irc, kSecAttrProtocolIRC as String), (.nntp, kSecAttrProtocolNNTP as String),
        (.pop3, kSecAttrProtocolPOP3 as String), (.smtp, kSecAttrProtocolSMTP as String), (.socks, kSecAttrProtocolSOCKS as String),
        (.imap, kSecAttrProtocolIMAP as String), (.ldap, kSecAttrProtocolLDAP as String), (.appleTalk, kSecAttrProtocolAppleTalk as String),
        (.afp, kSecAttrProtocolAFP as String), (.telnet, kSecAttrProtocolTelnet as String), (.ssh, kSecAttrProtocolSSH as String),
        (.ftps, kSecAttrProtocolFTPS as String), (.https, kSecAttrProtocolHTTPS as String), (.httpProxy, kSecAttrProtocolHTTPProxy as String),
        (.httpsProxy, kSecAttrProtocolHTTPSProxy as String), (.ftpProxy, kSecAttrProtocolFTPProxy as String), (.smb, kSecAttrProtocolSMB as String),
        (.rtsp, kSecAttrProtocolRTSP as String), (.rtspProxy, kSecAttrProtocolRTSPProxy as String), (.daap, kSecAttrProtocolDAAP as String),
        (.eppc, kSecAttrProtocolEPPC as String), (.ipp, kSecAttrProtocolIPP as String), (.nntps, kSecAttrProtocolNNTPS as String),
        (.ldaps, kSecAttrProtocolLDAPS as String), (.telnetS, kSecAttrProtocolTelnetS as String), (.imaps, kSecAttrProtocolIMAPS as String),
        (.ircs, kSecAttrProtocolIRCS as String), (.pop3S, kSecAttrProtocolPOP3S as String),
    ])
    func protocolsMatchSecurityConstants(value: InternetProtocol, constant: String) {
        #expect(value.rawValue == constant)
    }

    @Test(arguments: [
        (AuthenticationType.ntlm, kSecAttrAuthenticationTypeNTLM as String), (.msn, kSecAttrAuthenticationTypeMSN as String),
        (.dpa, kSecAttrAuthenticationTypeDPA as String), (.rpa, kSecAttrAuthenticationTypeRPA as String),
        (.httpBasic, kSecAttrAuthenticationTypeHTTPBasic as String), (.httpDigest, kSecAttrAuthenticationTypeHTTPDigest as String),
        (.htmlForm, kSecAttrAuthenticationTypeHTMLForm as String), (.default, kSecAttrAuthenticationTypeDefault as String),
    ])
    func authenticationTypesMatchSecurityConstants(value: AuthenticationType, constant: String) {
        #expect(value.rawValue == constant)
    }
}
