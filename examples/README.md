# Examples

Runnable TypeScript examples for `@forgesworn/ring-sig`.

## Prerequisites

Install dependencies from the repo root:

```bash
npm install
```

## Running the examples

Use `npx tsx` to run TypeScript directly — no build step required.

### SAG — Anonymous group membership proof

```bash
npx tsx examples/basic-sag.ts
```

Demonstrates:
- Generating a ring of public keys
- Signing a message anonymously as one member of the ring
- Verifying the ring signature
- Tamper detection (modified message, modified ring)
- JSON serialisation and round-trip verification
- Custom domain separators for cross-application isolation

### LSAG — Anonymous voting with double-vote detection

```bash
npx tsx examples/basic-lsag.ts
```

Demonstrates:
- Anonymous voting where each voter stays hidden within the ring
- Double-vote detection via deterministic key images
- Pre-computing key images to check eligibility before signing
- Cross-context unlinkability — the same key produces different key images for different elections

## Key format

All examples use x-only public keys (32 bytes, 64 hex characters) following the BIP-340 convention used by Nostr and Bitcoin Taproot:

```typescript
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';

const priv = bytesToHex(secp256k1.utils.randomPrivateKey());
// x-only: compressed (33 bytes) minus the 02/03 prefix = 32 bytes
const pub = bytesToHex(secp256k1.getPublicKey(priv, true)).slice(2);
```
