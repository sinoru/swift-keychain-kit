# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Keychain` with add, search, update, and delete operations over Keychain Services,
  each in a synchronous form and an `async` form that runs off the caller's actor.
- Typed `Item`, `Attributes`, and `Query` for generic passwords, internet passwords,
  cryptographic keys, certificates, and identities, with attributes exposed as
  properties only on the item classes they are valid for.
- `KeychainError`, a typed error that keeps the original `OSStatus`.
- Password conveniences for creating and reading password items.
- Key generation, including Secure Enclave keys, and signing and verification through
  `KeyReference`.
- `CertificateReference` created from DER, and identity lookup with access to the
  private key and certificate.
- Item protection through accessibility levels and `AccessControl`, and
  `AuthenticationContext` for supplying an `LAContext` to a query.
- Access groups for sharing items, and the file-based keychain as an opt-in storage
  on macOS.
- DocC documentation catalog.
- Support for macOS 12, iOS 15, tvOS 15, watchOS 9, and visionOS 1 with Swift 6.2.

[unreleased]: https://github.com/sinoru/swift-keychain-kit/commits/main
