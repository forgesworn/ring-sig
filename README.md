# @forgesworn/ring-sig

**Nostr:** [`npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2`](https://njump.me/npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2)

[![npm](https://img.shields.io/npm/v/@forgesworn/ring-sig)](https://www.npmjs.com/package/@forgesworn/ring-sig)
[![CI](https://github.com/forgesworn/ring-sig/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/ring-sig/actions/workflows/ci.yml)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

SAG and LSAG ring signatures on secp256k1.

**Prove group membership without revealing identity.**

## Use cases

- **Anonymous group membership proofs** — prove you are one of N key holders without revealing which one
- **Whistleblowing** — sign a statement as "a member of this organisation" without self-identifying
- **Privacy-preserving attestation** — "a licensed professional verified this" without naming the professional (pairs with [nostr-attestations](https://github.com/forgesworn/nostr-attestations) for on-chain anonymous endorsements)
- **Double-action prevention** (LSAG) — detect if the same key signs twice in the same context, without linking signatures across contexts

## Install

```bash
npm install @forgesworn/ring-sig
```

## Usage

### SAG — Spontaneous Anonymous Group signatures

```typescript
import { ringSign, ringVerify } from '@forgesworn/ring-sig';

// A ring of x-only public keys (32 bytes, hex)
const ring = [pubkey0, pubkey1, pubkey2, pubkey3];

// Sign as ring member at index 2
const sig = ringSign('my message', ring, 2, privateKey2);

// Anyone can verify the signature is from a ring member
const valid = ringVerify(sig); // true
```

### LSAG — Linkable SAG (double-action detection via key images)

```typescript
import { lsagSign, lsagVerify, computeKeyImage, hasDuplicateKeyImage } from '@forgesworn/ring-sig';

const electionId = 'vote-2026-q1';
const ring = [pubkey0, pubkey1, pubkey2];

// Sign
const sig = lsagSign('candidate-A', ring, 0, privateKey0, electionId);

// Verify
const valid = lsagVerify(sig); // true

// Detect double-signing: key images are deterministic per (key, electionId) pair
const keyImage = computeKeyImage(privateKey0, pubkey0, electionId);
const isDuplicate = hasDuplicateKeyImage(keyImage, existingKeyImages);
```

## Domain separators

Both `ringSign` and `lsagSign` accept an optional `domain` parameter (defaults to `'sag-v1'` / `'lsag-v1'`). Pass a custom domain if you need cross-protocol isolation:

```typescript
const sig = ringSign(message, ring, index, privateKey, 'my-app-v1');
```

## Error classes

- `RingSignatureError` — base class
- `ValidationError` — malformed inputs, bounds exceeded
- `CryptoError` — invalid keys, failed operations

## Cryptography

- **SAG** (Spontaneous Anonymous Group): Schnorr-based ring signature. Signature size is O(n) with the ring.
- **LSAG** (Linkable SAG): Adds a deterministic key image `I = x * H_p(P || context)`. Signatures by the same key in the same context produce identical key images, enabling double-action detection without cross-context linkability.
- Domain separation: `'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`
- Maximum ring size: 1000 members

## Part of the ForgeSworn Toolkit

[ForgeSworn](https://forgesworn.dev) builds open-source cryptographic identity, payments, and coordination tools for Nostr.

| Library | What it does |
|---------|-------------|
| [nsec-tree](https://github.com/forgesworn/nsec-tree) | Deterministic sub-identity derivation |
| [ring-sig](https://github.com/forgesworn/ring-sig) | SAG/LSAG ring signatures on secp256k1 |
| [range-proof](https://github.com/forgesworn/range-proof) | Pedersen commitment range proofs |
| [canary-kit](https://github.com/forgesworn/canary-kit) | Coercion-resistant spoken verification |
| [spoken-token](https://github.com/forgesworn/spoken-token) | Human-speakable verification tokens |
| [toll-booth](https://github.com/forgesworn/toll-booth) | L402 payment middleware |
| [geohash-kit](https://github.com/forgesworn/geohash-kit) | Geohash toolkit with polygon coverage |
| [nostr-attestations](https://github.com/forgesworn/nostr-attestations) | NIP-VA verifiable attestations |
| [dominion](https://github.com/forgesworn/dominion) | Epoch-based encrypted access control |
| [nostr-veil](https://github.com/forgesworn/nostr-veil) | Privacy-preserving Web of Trust |

## Licence

MIT
