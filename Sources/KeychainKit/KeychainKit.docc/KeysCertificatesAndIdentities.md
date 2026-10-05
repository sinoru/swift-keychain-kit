# Keys, Certificates, and Identities

Generate keys, use them, and keep them, certificates, and identities in the keychain.

## Overview

A password item holds secret data. A key, a certificate, or an identity is an object of
the Security framework instead, so an ``Item`` of those classes carries a reference where
a password carries data: a ``KeyReference``, a ``CertificateReference``, or an
``IdentityReference``. Each wraps the framework's own object, available as `reference`
for the APIs that take a `SecKey`, a `SecCertificate`, or a `SecIdentity`.

### Generate a key

`generateKey(_:sizeInBits:attributes:)` creates a private key and stores it. The
attributes describe the stored key; give it an `applicationTag` to find it by later.

```swift
var attributes = Attributes<CryptographicKey>()
attributes.applicationTag = Data("com.example.keys.signing".utf8)
attributes.label = "Signing key"

let key = try keychain.generateKey(.ecSECPrimeRandom, sizeInBits: 256, attributes: attributes)
```

Only the private key is stored. The public key is derived from it when needed:

```swift
let publicKey = key.publicKey
```

A key that should not be stored at all comes from ``KeyReference`` directly:

```swift
let ephemeral = try KeyReference(generating: .ecSECPrimeRandom, sizeInBits: 256)
```

### Find a key

A ``Query`` for keys matches on the key attributes. `fetchFirstReference(matching:)` returns the
key alone, and `fetchFirst(matching:)` returns it together with its attributes.

```swift
var query = Query<CryptographicKey>()
query.applicationTag = Data("com.example.keys.signing".utf8)
query.keyClass = .private

let key = try keychain.fetchFirstReference(matching: query)   // KeyReference?
let item = try keychain.fetchFirst(matching: query)            // Item? with attributes and reference
let keys = try keychain.fetchReferences(matching: Query<CryptographicKey>())
```

An existing key is added like any other item, with the reference as its value:

```swift
var item = Item<CryptographicKey>(reference: ephemeral)
item.applicationTag = Data("com.example.keys.imported".utf8)
try keychain.add(item)
```

### Sign, encrypt, and exchange keys

A ``KeyAlgorithm`` names what an operation does and what it expects: a `Digest` signature
algorithm takes a digest you computed, a `Message` algorithm hashes the input itself.
`supports(_:for:)` tells whether a key can perform a ``KeyOperation`` with an algorithm.

```swift
let message = Data("message".utf8)

let signature = try key.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
let isValid = try publicKey.isValidSignature(signature, for: message, using: .ecdsaSignatureMessageX962SHA256)

let ciphertext = try publicKey.encryptedData(for: message, using: .eciesEncryptionCofactorVariableIVX963SHA256AESGCM)
let plaintext = try key.decryptedData(for: ciphertext, using: .eciesEncryptionCofactorVariableIVX963SHA256AESGCM)

let secret = try key.keyExchangeResult(with: theirPublicKey, using: .ecdhKeyExchangeStandard)
```

`isValidSignature(_:for:using:)` returns `false` for a signature that does not match or
is malformed, and throws for anything else, such as an algorithm the key does not support.

An operation with a stored key goes through the keychain daemon and may wait for the user
to authenticate, so each of these, and key generation, has an `async` form that runs off
the caller's actor.

```swift
let signature = try await key.signature(for: message, using: .ecdsaSignatureMessageX962SHA256)
```

### Keep a key in the Secure Enclave

A Secure Enclave key never leaves the hardware: it cannot be exported, and only the device
that made it can use it. The Secure Enclave works only with 256-bit NIST P curve keys, so
`generateSecureEnclaveKey(applicationTag:label:accessGroup:accessibility:constraints:authenticationContext:)`
takes neither a type nor a size. It always adds the `privateKeyUsage` flag, without which
the key could not sign; `constraints` adds to it.

```swift
let key = try keychain.generateSecureEnclaveKey(
    applicationTag: Data("com.example.keys.enclave".utf8),
    constraints: .biometryAny,
)
```

The key is found and used like any other. Generation fails on a device without a Secure
Enclave.

> Important: The simulator emulates the Secure Enclave without enforcing its rules, and
> does not enforce an application password either. Test these on a device.

### Protect a key

A key takes the same ``Protection`` as a password. When the access control asks for an
application password, pass the ``AuthenticationContext`` that holds it to the generation
call, as you would to `add(_:authenticationContext:)`.

```swift
let context = LAContext()
context.setCredential(Data("application password".utf8), type: .applicationPassword)

var attributes = Attributes<CryptographicKey>()
attributes.applicationTag = Data("com.example.keys.protected".utf8)
attributes.protection = .accessControl(try AccessControl(accessibility: .whenUnlocked, flags: .applicationPassword))

let key = try keychain.generateKey(
    .ecSECPrimeRandom,
    sizeInBits: 256,
    attributes: attributes,
    authenticationContext: AuthenticationContext(context),
)
```

### Import and export a key

A key converts to and from its external representation: PKCS #1 for an RSA key, and
ANSI X9.63 (`04 || X || Y [|| K]`) for an elliptic curve key.

```swift
let data = try key.externalRepresentation()
let restored = try KeyReference(externalRepresentation: data, keyType: .ecSECPrimeRandom, keyClass: .private)
```

That representation is what connects a key to CryptoKit. The NIST curve keys of CryptoKit
expose the same X9.63 form:

```swift
import CryptoKit

let cryptoKitKey = P256.Signing.PrivateKey()
let reference = try KeyReference(
    externalRepresentation: cryptoKitKey.x963Representation,
    keyType: .ecSECPrimeRandom,
    keyClass: .private,
)

let roundTripped = try P256.Signing.PrivateKey(x963Representation: reference.externalRepresentation())
```

CryptoKit keys without an X9.63 form, such as `Curve25519` keys and `SymmetricKey`, are
not key items. Apple's guidance is to store their raw representation as a generic
password, which `Item(service:account:data:)` does.

### Store a certificate

A certificate is created from its DER encoding and added by reference. Its attributes are
derived by the framework, so they are read-only on an item and usable as criteria on a
query.

```swift
guard let certificate = CertificateReference(derRepresentation: der) else {
    // Not a valid DER-encoded X.509 certificate.
    return
}
try keychain.add(Item<Certificate>(reference: certificate))

let stored = try keychain.fetchFirst(matching: Query<Certificate>())
let subject = stored?.subject                      // the X.500 subject name, DER-encoded
let certifiedKey = stored?.reference?.publicKey    // KeyReference?
```

The name and serial number attributes are DER-encoded bytes. KeychainKit does not parse
certificates or evaluate trust.

### Use an identity

An identity is a certificate paired with its private key. It is not added as an item of
its own: the keychain reports one wherever it holds both halves.

```swift
if let identity = try keychain.fetchFirstReference(matching: Query<Identity>()) {
    let certificate = try identity.certificate()
    let privateKey = try identity.privateKey()
}
```

### Mind the file-based keychain on macOS

The file-based keychain differs from the data protection keychain for these classes. The
differences below were measured on macOS 26.

- A key made from an external representation cannot be added; only a key the keychain
  generated, or one imported with `SecItemImport`, can.
- Most attributes of a key are rejected in an update even when unchanged. Pass an item
  holding only the attributes to change, rather than an item that was read.
- An identity reports only its certificate's attributes, not its key's.
- ``CertificateType`` does not report the X.509 version there.
