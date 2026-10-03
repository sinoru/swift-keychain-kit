//
//  AccessGroupTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Security
import Testing

@testable import KeychainKit

@Suite struct AccessGroupTests {
    @Test func rejectsTheEmptyString() {
        #expect(AccessGroup(rawValue: "") == nil)
        #expect(AccessGroup(rawValue: "TEAM.com.example")?.rawValue == "TEAM.com.example")
    }

    @Test func keychainGroupJoinsTeamIDAndName() {
        #expect(AccessGroup.keychainGroup(teamID: "ABCDE12345", name: "com.example.shared").rawValue == "ABCDE12345.com.example.shared")
    }

    @Test func tokenGroupMatchesSecurityConstant() {
        #expect(AccessGroup.token.rawValue == kSecAttrAccessGroupToken as String)
    }
}
