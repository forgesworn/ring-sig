# CLAUDE.md — @forgesworn/ring-sig

AI agent instructions for working on this codebase.

## Build & Test

```bash
npm run build      # tsc → dist/
npm test           # vitest (single run)
npm run typecheck  # tsc --noEmit
```

Always run `npm test` after changes. Always run `npm run typecheck` before committing.

## Architecture

| File | Purpose |
|------|---------|
| `src/sag.ts` | SAG (Spontaneous Anonymous Group) ring signatures — `ringSign`, `ringVerify` |
| `src/lsag.ts` | LSAG (Linkable SAG) — `lsagSign`, `lsagVerify`, `computeKeyImage`, `hasDuplicateKeyImage` |
| `src/utils.ts` | Shared crypto helpers — `hashToScalar`, `hashToPoint`, `randomScalar`, `safeMultiply`, `constantTimeEqual`, `scalarEqual` |
| `src/errors.ts` | Error hierarchy: `RingSignatureError` → `ValidationError`, `CryptoError` |
| `src/index.ts` | Public API re-exports |

### Data flow

- Public keys are x-only hex (32 bytes, BIP-340 convention). Internally converted to curve points via `'02' + hex` (even y).
- Private keys are 32-byte hex scalars reduced mod N.
- SAG: Schnorr-based ring — cyclic challenge chain `c_0 → c_1 → ... → c_0`.
- LSAG: Extends SAG with a second chain through `H_p(P || electionId)` and the key image `I = x * H_p(P || electionId)`.

## Crypto Safety — Do Not Change Without Expert Review

- **Domain separators** (`'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`) are protocol constants. Changing them breaks all existing signatures.
- **Nonces must be random** (via `secp256k1.utils.randomPrivateKey()`). Never use deterministic nonces — reusing a nonce leaks the private key.
- **BIP-340 parity fix** (negating `x` when `x*G` has odd y) is critical for x-only pubkey compatibility. Do not remove or reorder.
- **Length-prefixed hashing** in `hashToScalar` is intentional — it prevents domain separation ambiguity when concatenating variable-length fields.
- **Constant-time comparisons** (`constantTimeEqual`, `scalarEqual`) prevent timing side-channels. Do not replace with `===` or `Buffer.equals`.
- **`safeMultiply`** handles the `0n` edge case that `@noble/curves` rejects. Do not replace with bare `.multiply()`.
- **Key image format** is enforced as compressed point (02/03 prefix) to prevent duplicate images via different encodings of the same point.

## Conventions

- **British English** in all prose (colour, initialise, behaviour, licence).
- **ESM-only** — all imports use `.js` extensions.
- **Commit messages**: `type: description` (e.g. `feat: add batch verification`, `fix: reject identity point as key image`).
- **No `Co-Authored-By`** lines in commits.
- **Semantic-release on main** — every push to main auto-publishes. Work on branches; merge to main only when complete.

## Testing

Tests are in `tests/`. Vitest is the runner. Tests cover:
- Round-trip sign/verify for both SAG and LSAG
- Input validation (ring size, index bounds, duplicates)
- Key image determinism and duplicate detection
- Signature tampering detection
- Edge cases (wrong key, modified ring, altered message)

When adding new functionality, add corresponding tests. PRs touching signature logic require crypto review.
