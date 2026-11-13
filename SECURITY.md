# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** by email to
**apoman123@gmail.com**, not in a public issue or pull request. Include the
version, the platform, what an attacker can achieve and the steps to
reproduce. You will get an answer within a few days; please give us a
reasonable time to release a fix before disclosing the issue.

Especially relevant: anything that lets a website, a link, another program or
a network attacker make the signer sign something the user did not confirm,
sign outside the pinned constants (delegate, code hash, attestation address,
allow-list, bounds), or leak a private key, mnemonic, keystore password or
session cookie.

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x | yes |
| < 0.5 | no |

## Verifying releases

Every release file is built by GitHub Actions from the tagged commit and has a
build provenance attestation; see [Verify a download](README.md#verify-a-download).
