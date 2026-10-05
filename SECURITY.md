# Security

KeychainKit stores and retrieves secrets, so a defect in it can expose them. This document
describes how to report one.

## Reporting a Vulnerability

Report a known or suspected vulnerability privately through
[GitHub's private vulnerability reporting](https://github.com/sinoru/swift-keychain-kit/security/advisories/new).
**Do not file a public issue.**

Report when:

* You think you have discovered a potential security vulnerability in KeychainKit.
* You are unsure how a vulnerability affects KeychainKit.

A report is most useful with the affected version or commit, the platform and OS version,
and the steps or code that reproduce the problem.

## What Happens Next

* The report is acknowledged, possibly with a request for more detail on reproducing it.
* Once a fix is identified, you may be asked to validate it.
* The fix is released, and a security advisory crediting the reporter is published on
  GitHub.

## Scope

KeychainKit is an interface to Keychain Services. A vulnerability in Keychain Services, the
Security framework, or the Secure Enclave itself belongs with
[Apple](https://support.apple.com/102549); one in how KeychainKit builds a request, reads a
result, or documents the framework's behaviour belongs here.
