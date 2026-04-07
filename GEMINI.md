# GEMINI.md -- ring-sig

SAG and LSAG ring signatures on secp256k1 -- prove group membership without revealing identity.

## Commands

- `npm run build` -- compile TypeScript to dist/
- `npm test` -- run all tests (vitest)
- `npm run typecheck` -- type-check without emitting

## Dependencies

Runtime (2 packages):
- **`@noble/curves`** -- secp256k1 elliptic curve operations (point arithmetic, scalar math)
- **`@noble/hashes`** -- SHA-256 and hash utilities for domain-separated challenge hashing

## Structure

```
src/
  index.ts      -- public API barrel re-export
  sag.ts        -- SAG: ringSign, ringVerify, RingSignature, MAX_RING_SIZE
  lsag.ts       -- LSAG: lsagSign, lsagVerify, computeKeyImage, hasDuplicateKeyImage, LsagSignature
  utils.ts      -- hashToScalar, hashToPoint, randomScalar, safeMultiply, constantTimeEqual, scalarEqual
  errors.ts     -- RingSignatureError → ValidationError, CryptoError
tests/
  sag.test.ts   -- SAG test suite
  lsag.test.ts  -- LSAG test suite
examples/
  basic-sag.ts       -- SAG sign/verify walkthrough with tamper detection
  basic-lsag.ts      -- LSAG anonymous voting with double-vote detection
  voting-lsag.ts     -- LSAG voting example with pre-computed key images
dist/            -- build output (generated)
```

## Conventions

- **British English** -- colour, initialise, behaviour, licence
- **ESM-only** -- `"type": "module"` in package.json; all imports use `.js` extensions
- **TDD** -- write a failing test first, then implement
- **Input validation** -- all public APIs validate inputs and throw `ValidationError` or `CryptoError`
- **Constant-time comparisons** -- use `constantTimeEqual` / `scalarEqual` for secrets, never `===`
- **Commit messages** -- `type: description` format (feat:, fix:, docs:, chore:, refactor:). No Co-Authored-By lines.

## Key Patterns

- Public keys are x-only hex (32 bytes, 64 hex chars) per BIP-340. Internally converted to curve points via `'02' + hex` (even y).
- Private keys are 32-byte hex scalars. BIP-340 parity fix (negate `x` when `x*G` has odd y) is applied in both `ringSign` and `lsagSign`.
- Domain separators (`'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`) are protocol constants -- never change them.
- `safeMultiply` wraps `@noble/curves` `.multiply()` to handle the `0n` edge case that the library rejects.
- Key images (LSAG) are deterministic: `I = x * H_p(P || electionId)`. Same key in same election always produces the same image. Different elections produce unrelated images (cross-context unlinkability).
- Key image format is enforced as compressed point (02/03 prefix, 33 bytes) to prevent duplicate representations of the same point.
- Nonces are always random (`secp256k1.utils.randomPrivateKey()`). Deterministic nonces would leak the private key.

## Testing

62 tests across 2 files. Run `npm test` before committing. Run `npm run typecheck` to verify types.

Coverage includes: round-trip sign/verify for SAG and LSAG, input validation, key image determinism, duplicate detection, tamper detection, edge cases (wrong key, modified ring, altered message).

## Release

Automated via semantic-release. `feat:` = minor, `fix:` = patch, `BREAKING CHANGE:` in commit body = major. `chore:`, `docs:`, `refactor:` produce no release. GitHub Actions uses OIDC trusted publishing.
