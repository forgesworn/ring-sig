# AGENTS.md — ring-sig

Instructions in this file apply to the entire repository.

## Project Summary

- SAG and LSAG ring signatures on secp256k1.
- Proves group membership without revealing identity.
- ESM-only TypeScript package (`"type": "module"`).
- Zero runtime dependencies beyond `@noble/curves` and `@noble/hashes`.
- Automated publishing via semantic-release on push to `main`.

## Key Commands

- `npm run build` — compile TypeScript into `dist/`
- `npm test` — run the Vitest suite (single run)
- `npm run typecheck` — type-check without emitting

## Repository Structure

- `src/sag.ts` — SAG (Spontaneous Anonymous Group): `ringSign`, `ringVerify`, `MAX_RING_SIZE`, `RingSignature`
- `src/lsag.ts` — LSAG (Linkable SAG): `lsagSign`, `lsagVerify`, `computeKeyImage`, `hasDuplicateKeyImage`, `LsagSignature`
- `src/utils.ts` — shared crypto helpers: `hashToScalar`, `hashToPoint`, `randomScalar`, `safeMultiply`, `constantTimeEqual`, `scalarEqual`
- `src/errors.ts` — error hierarchy: `RingSignatureError` → `ValidationError`, `CryptoError`
- `src/index.ts` — public API barrel re-export
- `tests/sag.test.ts` — SAG test suite (23 tests)
- `tests/lsag.test.ts` — LSAG test suite (39 tests)
- `examples/` — runnable usage examples (`basic-sag.ts`, `basic-lsag.ts`, `voting-lsag.ts`)
- `dist/` — build output (generated, do not edit by hand)

## Coding Conventions

- British English in all identifiers and prose: `colour`, `initialise`, `behaviour`, `licence`.
- ESM-only — all imports use `.js` extensions. Do not use CommonJS.
- All public APIs validate inputs and throw typed errors (`ValidationError` or `CryptoError`).
- Constant-time comparisons (`constantTimeEqual`, `scalarEqual`) for any secret comparison — never `===` or `Buffer.equals`.
- `safeMultiply` must be used instead of bare `.multiply()` to handle the `0n` scalar edge case.

## Working Guidelines

- Run `npm test` after every change. Run `npm run typecheck` before committing.
- Do not edit generated output in `dist/` by hand.
- Never change domain separators (`'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`) — they are protocol constants and changing them breaks all existing signatures.
- Never use deterministic nonces — reusing a nonce leaks the private key.
- Do not remove the BIP-340 parity fix (negating `x` when `x*G` has odd y) — it is required for x-only pubkey compatibility.
- Any change to signature logic requires corresponding tests. Crypto changes require expert review.
- Work on branches; merge to `main` only when a logical chunk is complete. Semantic-release auto-publishes on every push to `main`.

## Release Notes

- Automated via semantic-release. `fix:` = patch, `feat:` = minor, `BREAKING CHANGE:` in commit body = major.
- `chore:`, `docs:`, `refactor:` do not trigger a release.
- GitHub Actions uses OIDC trusted publishing — no `NPM_TOKEN` needed.
- Tests must pass before any release-related changes are considered complete.
