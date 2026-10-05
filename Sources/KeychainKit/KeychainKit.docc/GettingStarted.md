# Getting Started

Store, find, update, and delete passwords, then protect and share them.

## Overview

A ``Keychain`` holds only configuration, so create one where convenient and share it
freely; it is `Sendable`. With no arguments it targets the data protection keychain,
which is the only keychain on iOS and relatives and the recommended one on macOS.

This article covers passwords. Keys, certificates, and identities use the same operations
and are described in <doc:KeysCertificatesAndIdentities>.

```swift
import KeychainKit

let keychain = Keychain()
```

### Add a password

``Item`` has convenience initializers for the two password classes. Adding an item whose
primary key already exists fails with ``KeychainError/Code/duplicateItem``.

```swift
let item = Item(service: "com.example.app", account: "alice", password: "s3cret")
let reference = try keychain.add(item)   // a PersistentReference you may keep or ignore
```

Any attribute can be set as a property before adding:

```swift
var item = Item(service: "com.example.app", account: "alice", password: "s3cret")
item.label = "Example account"
item.synchronizable = true
```

### Find passwords

A ``Query`` names the attributes an item must have, as the same properties. The method you pass it to decides how
many items come back and in what form. Nothing matching is not an error.

```swift
let query = Query(service: "com.example.app", account: "alice")

let item = try keychain.fetchFirst(matching: query)                  // Item? with attributes and data
let secret = try keychain.fetchFirstData(matching: query)            // Data?
let attributes = try keychain.fetchFirstAttributes(matching: query)  // Attributes?

let everything = try keychain.fetch(matching: Query(service: "com.example.app"))   // [Item]
```

An item behind an access control object authenticates for its attributes as it does for
its data. `fetch(matching:)` reads everything in one call on the data protection keychain. The
file-based keychain on macOS returns data for only one password item at a time, so there it
fetches each item's data in a second call; use `fetchAttributes(matching:)` when the data is
not needed.

### Update and delete

```swift
var changes = Item<GenericPassword>()
changes.password = "n3w"
changes.comment = "Rotated"
try keychain.update(matching: query, with: changes)   // throws itemNotFound if nothing matches

try keychain.delete(matching: query)                  // nothing matching is fine
```

### Call from Swift concurrency

Every operation has an `async` overload. The compiler picks it automatically in an
asynchronous context. The call runs on the global concurrent executor rather than the
caller's actor, and it cannot be cancelled once started.

```swift
let item = try await keychain.fetchFirst(matching: query)
```

### Protect an item

Set ``Attributes/protection`` to either an ``Accessibility`` level or an
``AccessControl`` that adds user presence. Creating an access control validates it
immediately.

```swift
var item = Item(service: "com.example.bank", account: "alice", password: "s3cret")
item.attributes.protection = .accessible(.whenPasscodeSetThisDeviceOnly)

let control = try AccessControl(accessibility: .whenUnlocked, flags: .userPresence)
item.attributes.protection = .accessControl(control)
```

An item that syncs through iCloud Keychain cannot have an access control, even one with no
flags: adding it fails with `errSecParam`. Give a synchronizable item an ``Accessibility``
level instead.

To read such an item without a second prompt, or to control the prompt, pass an
``AuthenticationContext``:

```swift
let context = LAContext()
context.localizedReason = "Unlock your account"

let query = Query(service: "com.example.bank", account: "alice")
let item = try keychain.fetchFirst(matching: query, authenticationContext: AuthenticationContext(context))
```

### Share items between your apps

Items belong to exactly one ``AccessGroup``. Set a default on the ``Keychain`` or name one
per item or query. The app must belong to the group through its entitlements, or the
operation, search or add, fails with ``KeychainError/Code/missingEntitlement``.

```swift
let shared = Keychain(accessGroup: .keychainGroup(teamID: "ABCDE12345", name: "com.example.shared"))
try shared.add(Item(service: "com.example.sso", account: "alice", password: "s3cret"))
```

### Choose a keychain on macOS

``Storage/dataProtection`` is the default everywhere. On macOS, code that runs outside a
user session, such as a `launchd` daemon, must use the file-based keychain instead:

```swift
#if os(macOS)
let daemonKeychain = Keychain(storage: .fileBased())
#endif
```

Calls made through it stay in the file-based keychain. Access groups and accessibility levels
do not apply there and are ignored, while an access control object, a token such as the
Secure Enclave, a synchronizable item, and the `token` access group fail with
``KeychainError/Code/invalidParameter``. It also treats keys and identities differently; see
<doc:KeysCertificatesAndIdentities>.

### Handle errors

Every operation throws ``KeychainError``, which keeps the original `OSStatus` and
classifies the well-known values as a ``KeychainError/Code``.

```swift
do {
    try keychain.add(item)
} catch let error where error.code == .duplicateItem {
    try keychain.update(matching: query, with: item)
}
```
