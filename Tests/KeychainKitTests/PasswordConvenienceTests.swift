//
//  PasswordConvenienceTests.swift
//  KeychainKitTests
//
//  Copyright (c) 2026 Kang Jaehong
//  SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Testing

@testable import KeychainKit
import KeychainKitTestSupport

@Suite struct PasswordConvenienceTests {
    @Test func genericPasswordInitializersSetPrimaryKeyAndData() {
        let item = Item(service: "service", account: "account", password: "pa55")
        #expect(item[.service] == "service")
        #expect(item[.account] == "account")
        #expect(item.data == Data("pa55".utf8))
        #expect(item.password == "pa55")
        #expect(Item(service: "service", account: "account", data: Data([1])).data == Data([1]))
    }

    @Test func internetPasswordInitializersSetOnlyWhatIsGiven() {
        let minimal = Item(server: "example.com", account: "account", password: "pa55")
        #expect(minimal[.server] == "example.com")
        #expect(minimal[.account] == "account")
        #expect(minimal[.port] == nil)
        #expect(minimal[.internetProtocol] == nil)

        let full = Item(
            server: "example.com", account: "account", data: Data([1]),
            internetProtocol: .https, port: 8443, path: "/api", authenticationType: .httpBasic,
        )
        #expect(full[.internetProtocol] == .https)
        #expect(full[.port] == 8443)
        #expect(full[.path] == "/api")
        #expect(full[.authenticationType] == .httpBasic)
    }

    @Test func passwordRoundTripsThroughData() {
        var item = Item<GenericPassword>()
        item.password = "secret"
        #expect(item.data == Data("secret".utf8))
        item.password = nil
        #expect(item.data == nil)
        item.data = Data([0xFF, 0xFE])
        #expect(item.password == nil)
    }

    @Test func queryInitializersMatchTheItemsTheyDescribe() throws {
        let backend = InMemoryKeychainBackend()
        let keychain = Keychain(backend: backend, storage: .dataProtection, accessGroup: nil)
        try keychain.add(Item(service: "service", account: "one", password: "1"))
        try keychain.add(Item(service: "service", account: "two", password: "2"))
        try keychain.add(Item(server: "example.com", account: "one", password: "3", port: 443))
        try keychain.add(Item(server: "example.com", account: "one", password: "4", port: 8443))

        #expect(try keychain.first(matching: Query(service: "service", account: "two"))?.password == "2")
        #expect(try keychain.all(matching: Query(service: "service")).count == 2)
        #expect(try keychain.first(matching: Query(server: "example.com", port: 8443))?.password == "4")
        #expect(try keychain.all(matching: Query(server: "example.com", account: "one")).count == 2)
    }
}
