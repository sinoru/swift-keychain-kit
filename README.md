# KeychainKit

[![GitHub Actions — Apple Platforms](https://github.com/sinoru/swift-keychain-kit/actions/workflows/apple-platforms.yml/badge.svg)](https://github.com/sinoru/swift-keychain-kit/actions/workflows/apple-platforms.yml)

**KeychainKit** is a Swift interface to Apple's Keychain Services. It replaces the
`CFDictionary`-of-`kSec*`-keys API with typed items, attributes, and queries; reports
failures as a typed error that keeps the original `OSStatus`; and offers every operation
in a synchronous form and an `async` form that stays off the caller's actor.

```swift
import KeychainKit

let keychain = Keychain()

try keychain.add(Item(service: "com.example.app", account: "alice", password: "s3cret"))

if let item = try keychain.first(matching: Query(service: "com.example.app", account: "alice")) {
    print(item.password ?? "")
}
```

## Table of Contents

* [Requirements](#requirements)
* [Getting Started](#getting-started)
* [Usage](#usage)
* [Design](#design)
* [Testing](#testing)
* [Roadmap](#roadmap)
* [License](#license)

## Requirements

* Swift 6.2 (Xcode 26) or later
* macOS 12, iOS 15, tvOS 15, watchOS 9, or visionOS 1

## Getting Started

Add the package to your `Package.swift` and `KeychainKit` to the target that uses it:

```swift
dependencies: [
    .package(url: "https://github.com/sinoru/swift-keychain-kit.git", branch: "main"),
]
```

```swift
.target(
    name: "MyTarget",
    dependencies: [
        .product(name: "KeychainKit", package: "swift-keychain-kit"),
    ]
),
```

## Usage

### Items, attributes, and queries

An `Item` belongs to one item class and carries `Attributes` plus optional secret `Data`.
Each attribute is a typed property that exists only for the classes it is valid for:
`service` on a generic password, `server` and `port` on an internet password, `label` and
`accessGroup` on anything. Using one on the wrong class does not compile.

```swift
var item = Item(server: "example.com", account: "alice", password: "s3cret", internetProtocol: .https)
item.label = "Example"
item.synchronizable = true
```

A `Query` names the attributes an item must have. The method you pass it to decides how
many items you get and in what shape; nothing matching is `nil` or `[]`, not an error.

```swift
let query = Query(service: "com.example.app", account: "alice")

try keychain.first(matching: query)        // Item?
try keychain.data(matching: query)         // Data?
try keychain.attributes(matching: query)   // Attributes?, never prompts
try keychain.all(matching: Query(service: "com.example.app"))   // [Item]

try keychain.update(matching: query, with: changes)   // throws .itemNotFound
try keychain.delete(matching: query)                  // idempotent
```

### Swift concurrency

Every operation has an `async` overload, selected automatically in an asynchronous
context. Keychain Services blocks the calling thread while it talks to `securityd`, so the
overloads are `@concurrent` and run on the global executor rather than the caller's actor.
`Keychain` itself is `Sendable`.

```swift
let item = try await keychain.first(matching: query)
```

### Protection

```swift
item.attributes.protection = .accessible(.whenPasscodeSetThisDeviceOnly)

let control = try AccessControl(accessibility: .whenUnlocked, flags: [.biometryCurrentSet, .or, .devicePasscode])
item.attributes.protection = .accessControl(control)

var query = Query(service: "com.example.bank", account: "alice")
query.authenticationContext = AuthenticationContext(context)   // an LAContext you configured
```

### Sharing and storage

```swift
let shared = Keychain(accessGroup: .keychainGroup(teamID: "ABCDE12345", name: "com.example.shared"))

#if os(macOS)
let daemon = Keychain(storage: .fileBased())   // for code outside a user session
#endif
```

The full guide lives in the DocC catalog under `Sources/KeychainKit/KeychainKit.docc`.

## Design

* **The framework's semantics, not a new model.** Primary keys, duplicate and not-found
  statuses, synchronizable matching, and the result shape per combination of return keys
  are the framework's; the types only make them visible.
* **Typed everywhere.** `Attributes` expose only the properties valid for their class; `KeychainError`
  preserves the `OSStatus` and classifies the documented codes; every operation uses typed
  throws.
* **Strict memory safety.** The package builds with strict memory safety, so the few calls
  that need it carry an `unsafe` marker. Everything else is plain Swift over a `Sendable`
  value model.
* **No locking of its own.** Keychain Services is thread-safe; the library does not
  serialize calls. Coordinating user-facing prompts is the caller's concern.
* **Data protection by default.** `kSecUseDataProtectionKeychain` is set on every call so
  macOS behaves like the other platforms. The file-based keychain is opt-in and macOS only.

## Testing

Tests never touch the user's keychain. The request-building and result-parsing halves of
every operation are pure functions and are tested directly. The calls into the framework are
tested on macOS against a temporary file-based keychain created in the temporary directory
and deleted afterwards. Data-protection behaviour such as access groups and biometrics
requires a signed host and is outside `swift test`.

```shell
swift test
swift test --sanitize=thread
```

## Roadmap

Key, certificate, and identity items, `SecKey` operations, and the Secure Enclave are
tracked in [#1](https://github.com/sinoru/swift-keychain-kit/issues/1).

## License

Apache License 2.0. See [LICENSE](LICENSE).
