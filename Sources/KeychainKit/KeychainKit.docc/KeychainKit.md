# ``KeychainKit``

A Swift interface to Keychain Services with typed attributes, typed errors, and
Swift concurrency built in.

## Overview

Keychain Services is a C API driven by `CFDictionary`s of `kSec*` keys. KeychainKit
replaces those dictionaries with Swift types: an ``Item`` of one ``ItemClass`` whose
``Attributes`` are typed properties declared only for the classes they apply to, a
``Query`` that describes what to find, and a ``Keychain`` whose operations return `nil`
or an empty array when nothing matches and throw a ``KeychainError`` otherwise. Passwords,
keys, certificates, and identities are all items; keys also sign, encrypt, and exchange
secrets through ``KeyReference``.

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
- <doc:KeysCertificatesAndIdentities>
- ``Keychain``
- ``KeychainError``

### Items and attributes

- ``Item``
- ``Attributes``
- ``ItemClass``
- ``PersistentReference``

### Passwords

- ``PasswordItemClass``
- ``GenericPassword``
- ``InternetPassword``
- ``InternetProtocol``
- ``AuthenticationType``

### Keys, certificates, and identities

- ``ReferenceItemClass``
- ``KeyItemClass``
- ``CertificateItemClass``
- ``CryptographicKey``
- ``Certificate``
- ``Identity``
- ``ItemReference``
- ``KeyReference``
- ``CertificateReference``
- ``IdentityReference``
- ``KeyClass``
- ``KeyType``
- ``TokenID``
- ``CertificateType``
- ``CertificateEncoding``

### Key operations

- ``KeyAlgorithm``
- ``KeyOperation``

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
