# Security Policy

## Audit Status

This library has not undergone a formal security audit. Use at your own risk in production.

## Algorithm

This library implements two ring signature schemes on the secp256k1 elliptic curve:

- **SAG** (Spontaneous Anonymous Group) signatures -- Schnorr-based ring signatures where signature size is O(n) in the number of ring members.
- **LSAG** (Linkable Spontaneous Anonymous Group) signatures -- extends SAG with deterministic key images, enabling detection of double-signing within a context without cross-context linkability.

## Academic References

- **Rivest, Shamir, Tauman (2001)** -- "How to Leak a Secret". The foundational paper introducing ring signatures, enabling a signer to prove membership in an ad hoc group without revealing which member signed.
- **Liu, Wei, Wong (2004)** -- "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups". Introduces linkability via key images: signatures by the same private key in the same context produce identical key images, enabling double-action detection.

## Security Properties

- **Signer ambiguity** -- a verifier can confirm the signature was produced by a member of the ring but cannot determine which member signed.
- **Unforgeability** -- a valid signature cannot be produced without knowledge of a private key corresponding to one of the ring's public keys.
- **Linkability (LSAG only)** -- if the same signer signs twice within the same context (e.g. election ID), the resulting key images are identical, allowing detection of double-signing. Signatures in different contexts remain unlinkable.

## Dependencies

Cryptographic primitives are provided by audited libraries:

- [`@noble/curves`](https://github.com/paulmillr/noble-curves) -- secp256k1 elliptic curve operations (audited by Cure53)
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) -- SHA-256 hashing (audited by Cure53)

## Known Limitations

- **O(n) signature size** -- signature size grows linearly with the number of ring members (maximum ring size: 1000).
- **Not constant-time in all operations** -- while constant-time comparisons are used for sensitive values, some higher-level operations may leak timing information about the ring structure.
- **Not post-quantum** -- ring signatures on secp256k1 are vulnerable to quantum attacks on the discrete logarithm problem.

## Reporting Vulnerabilities

Please report security vulnerabilities via [GitHub Security Advisories](https://github.com/forgesworn/ring-sig/security/advisories/new).

Do not open public issues for security-sensitive reports.
