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

The snippets are self-contained. They generate throwaway keys with `@noble/curves` and `@noble/hashes`, which this package already depends on; add both to your own `package.json` if you import them directly.

Key formats: public keys are x-only hex (32 bytes, 64 hex characters; case-insensitive, normalised to lowercase). Private keys must be exactly 64 lowercase hex characters and below the curve order; anything else throws `ValidationError`.

### SAG — Spontaneous Anonymous Group signatures

```typescript
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ringSign, ringVerify } from '@forgesworn/ring-sig';

// Four throwaway key pairs. schnorr.getPublicKey returns the x-only public key.
const members = Array.from({ length: 4 }, () => {
  const secretKey = schnorr.utils.randomSecretKey();
  return {
    privateKey: bytesToHex(secretKey),
    publicKey: bytesToHex(schnorr.getPublicKey(secretKey)),
  };
});

// The ring is the list of x-only public keys (32 bytes, hex)
const ring = members.map(m => m.publicKey);

// Sign as ring member at index 2
const sig = ringSign('my message', ring, 2, members[2].privateKey);

// Anyone can verify the signature is from a ring member, using only the signature.
// Returns false (never throws) for an invalid or malformed signature.
const valid = ringVerify(sig); // true
```

### LSAG — Linkable SAG (double-action detection via key images)

```typescript
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  lsagSign,
  lsagVerify,
  computeKeyImage,
  hasDuplicateKeyImage,
  type LsagSignature,
} from '@forgesworn/ring-sig';

const voters = Array.from({ length: 3 }, () => {
  const secretKey = schnorr.utils.randomSecretKey();
  return {
    privateKey: bytesToHex(secretKey),
    publicKey: bytesToHex(schnorr.getPublicKey(secretKey)),
  };
});
const ring = voters.map(v => v.publicKey);
const electionId = 'vote-2026-q1';

// Voter side: sign a ballot as ring member 0 (needs the private key)
const sig = lsagSign('candidate-A', ring, 0, voters[0].privateKey, electionId);

// Verifier side: a vote verifier has no private keys and only needs the signature.
// sig.keyImage is the key image; it is deterministic per (key, electionId) pair.
const acceptedKeyImages: string[] = []; // key images of ballots already accepted

function acceptBallot(ballot: LsagSignature): boolean {
  // lsagVerify checks the signature is internally consistent. It does not know which
  // election or ring you expect, so compare those yourself.
  if (ballot.electionId !== electionId) return false;
  if (ballot.ring.join() !== ring.join()) return false;
  if (!lsagVerify(ballot)) return false;
  if (hasDuplicateKeyImage(ballot.keyImage, acceptedKeyImages)) return false; // double vote
  acceptedKeyImages.push(ballot.keyImage);
  return true;
}

acceptBallot(sig); // true
acceptBallot(sig); // false: same key image already recorded

// Signer side only: computeKeyImage needs the private key. It returns the same value
// as sig.keyImage, so a voter can check in advance whether their image is already spent.
const keyImage = computeKeyImage(voters[0].privateKey, voters[0].publicKey, electionId);
// keyImage === sig.keyImage
```

`sig.keyImage` is a compressed point (66 hex characters). `hasDuplicateKeyImage` throws `ValidationError` if its first argument is not in that format, and expects `existingKeyImages` to be hex strings you stored from earlier `sig.keyImage` values.

### Limits and error behaviour

- Ring: 2 to 1000 members, no duplicates.
- `message` is a string of at most 65536 UTF-8 bytes. `electionId` is a non-empty string of at most 512 UTF-8 bytes.
- `ringSign`, `lsagSign` and `computeKeyImage` throw on invalid input, mostly `ValidationError` (ring size, index, duplicates, key format, key mismatch, length limits). A ring entry that is not a valid x-only curve point surfaces the underlying `@noble/curves` error, and a non-string ring entry a `TypeError`.
- `ringVerify` and `lsagVerify` never throw. Any malformed or invalid signature returns `false`.
- Scalars in a signature (`c0`, `responses`) must be exactly 64 lowercase hex characters below the curve order. Signatures produced by this library always are.

## Domain separators

Both `ringSign` and `lsagSign` accept an optional `domain` parameter (defaults to `'sag-v1'` / `'lsag-v1'`). Pass a custom domain if you need cross-protocol isolation. For `ringSign` it is the 5th argument; for `lsagSign` it is the 6th, after `electionId`:

```typescript
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ringSign, ringVerify, lsagSign, lsagVerify } from '@forgesworn/ring-sig';

const members = Array.from({ length: 3 }, () => {
  const secretKey = schnorr.utils.randomSecretKey();
  return {
    privateKey: bytesToHex(secretKey),
    publicKey: bytesToHex(schnorr.getPublicKey(secretKey)),
  };
});
const ring = members.map(m => m.publicKey);
const electionId = 'vote-2026-q1';

const sagSig = ringSign('my message', ring, 0, members[0].privateKey, 'my-app-v1');
const lsagSig = lsagSign('my message', ring, 0, members[0].privateKey, electionId, 'my-app-v1');

// The verify functions take only the signature and read the domain from it.
// There is no expected-domain parameter, so pin the domain yourself.
const APP_DOMAIN = 'my-app-v1';
const sagOk = sagSig.domain === APP_DOMAIN && ringVerify(sagSig); // true
const lsagOk = lsagSig.domain === APP_DOMAIN && lsagVerify(lsagSig); // true
```

When `sig.domain` is absent, the verifier uses the default (`'sag-v1'` for `ringVerify`, `'lsag-v1'` for `lsagVerify`). Signing with the default domain omits the field, and an explicit default is equivalent, so to pin the default compare `(sig.domain ?? 'lsag-v1') === 'lsag-v1'`. The domain is part of every challenge hash, so editing `domain` on an existing signature makes it fail verification. A signature validly made under any other domain still verifies as it stands, which is why the check above is needed for isolation between protocols. In the same way, verification does not know which ring, message or `electionId` you expect: compare `sig.ring`, `sig.message` and `sig.electionId` with your own values.

## Error classes

- `RingSignatureError`: base class
- `ValidationError`: malformed inputs, bounds exceeded, non-canonical scalars, key mismatch
- `CryptoError`: cryptographic failure inside the library (hash-to-point exhaustion); not expected in practice

## Upgrading

Breaking changes between major versions, with migration notes, are in [CHANGELOG.md](CHANGELOG.md). Coming from v2: scalars are now strictly validated (see the 3.0.0 entry). Signatures produced by this library always verify; only hand-encoded or re-encoded scalars are rejected.

## More documentation

- [llms.txt](llms.txt): concise API summary for LLMs and coding agents
- [llms-full.txt](llms-full.txt): full API reference with worked examples (both files ship in the npm package)

## Cryptography

- **SAG** (Spontaneous Anonymous Group): Schnorr-based ring signature. Signature size is O(n) with the ring.
- **LSAG** (Linkable SAG): Adds a deterministic key image `I = x * H_p(P || context)`. Signatures by the same key in the same context produce identical key images, enabling double-action detection without cross-context linkability.
- Domain separation: `'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`
- Maximum ring size: 1000 members (`MAX_RING_SIZE`, exported from the package entry point)

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
