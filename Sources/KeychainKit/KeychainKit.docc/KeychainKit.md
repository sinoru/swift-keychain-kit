# ``KeychainKit``

A Swift interface to Keychain Services with typed attributes, typed errors, and
Swift concurrency built in.

## Overview

Keychain Services is a C API driven by `CFDictionary`s of `kSec*` keys. KeychainKit
replaces those dictionaries with Swift types: an ``Item`` of one ``ItemClass`` whose
``Attributes`` accept only the keys valid for that class, a ``Query`` that describes
what to find, and a ``Keychain`` whose operations return `nil` or an empty array when
nothing matches and throw a ``KeychainError`` otherwise.

```swift
let keychain = Keychain()

try keychain.add(Item(service: "com.example.app", account: "alice", password: "s3cret"))

if let item = try keychain.first(matching: Query(service: "com.example.app", account: "alice")) {
    print(item.password ?? "")
}
```

Every operation also has an `async` form that runs off the caller's actor, because the
framework blocks the calling thread while it talks to the keychain daemon.

```swift
let item = try await keychain.first(matching: Query(service: "com.example.app", account: "alice"))
```

## Topics

### Essentials

- <doc:GettingStarted>
- ``Keychain``
- ``KeychainError``

### Items and attributes

- ``Item``
- ``Attributes``
- ``AttributeKey``
- ``ReadOnlyAttributeKey``
- ``ItemClass``
- ``PasswordItemClass``
- ``GenericPassword``
- ``InternetPassword``
- ``InternetProtocol``
- ``AuthenticationType``
- ``PersistentReference``

### Finding items

- ``Query``
- ``SynchronizableMatch``

### Protecting items

- ``Protection``
- ``Accessibility``
- ``AccessControl``
- ``AuthenticationContext``

### Storage and sharing

- ``Storage``
- ``FileKeychain``
- ``AccessGroup``

### Other item classes

These classes exist so the type system can name them, but their attribute keys and
operations are not implemented yet.

- ``CryptographicKey``
- ``Certificate``
- ``Identity``
