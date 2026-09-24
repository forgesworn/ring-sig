# AGENTS.md: ring-sig

Instructions in this file apply to the entire repository.

## Project Summary

- SAG and LSAG ring signatures on secp256k1.
- Proves group membership without revealing identity.
- ESM-only TypeScript package (`"type": "module"`).
- Zero runtime dependencies beyond `@noble/curves` (elliptic curve operations)
  and `@noble/hashes` (SHA-256 and hash utilities for domain-separated
  challenge hashing).

## Key Commands

- `npm run build`: compile TypeScript into `dist/`
- `npm test`: run the Vitest suite (single run)
- `npm run typecheck`: type-check without emitting

## Repository Structure

- `src/sag.ts`: SAG (Spontaneous Anonymous Group): `ringSign`, `ringVerify`, `MAX_RING_SIZE`, `RingSignature`
- `src/lsag.ts`: LSAG (Linkable SAG): `lsagSign`, `lsagVerify`, `computeKeyImage`, `hasDuplicateKeyImage`, `LsagSignature`
- `src/utils.ts`: shared crypto helpers: `hashToScalar`, `hashToPoint`, `randomScalar`, `safeMultiply`, `constantTimeEqual`, `scalarEqual`
- `src/errors.ts`: error hierarchy: `RingSignatureError` → `ValidationError`, `CryptoError`
- `src/index.ts`: public API barrel re-export
- `tests/sag.test.ts`: SAG test suite
- `tests/lsag.test.ts`: LSAG test suite
- `examples/`: runnable usage examples (`basic-sag.ts`, `basic-lsag.ts`, `voting-lsag.ts`, `sig-sizes.ts`)
- `dist/`: build output (generated, do not edit by hand)

## Data Flow

- Public keys are x-only hex (32 bytes, 64 hex chars) per BIP-340. Internally
  converted to curve points via `'02' + hex` (even y).
- Private keys are 32-byte hex scalars, reduced mod N.
- SAG: Schnorr-based ring, cyclic challenge chain `c_0 → c_1 → ... → c_0`.
- LSAG: extends SAG with a second chain through `H_p(P || electionId)` and the
  key image `I = x * H_p(P || electionId)`. The key image is deterministic:
  the same key in the same election always produces the same image, while
  different elections produce unrelated images (cross-context unlinkability).

## Coding Conventions

- British English in all identifiers and prose: `colour`, `initialise`, `behaviour`, `licence`.
- ESM-only: all imports use `.js` extensions. Do not use CommonJS.
- TDD: write a failing test first, then implement.
- All public APIs validate inputs and throw typed errors (`ValidationError` or `CryptoError`).
- Constant-time comparisons (`constantTimeEqual`, `scalarEqual`) for any secret comparison; never `===` or `Buffer.equals`.
- `safeMultiply` must be used instead of bare `.multiply()` to handle the `0n` scalar edge case.
- Commit messages: `type: description` (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`). No `Co-Authored-By` lines.

## Working Guidelines

- Run `npm test` after every change. Run `npm run typecheck` before committing.
- Do not edit generated output in `dist/` by hand.
- Never change domain separators (`'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`): they are protocol constants and changing them breaks all existing signatures.
- Never use deterministic nonces (always `randomScalar()`, backed by `secp256k1.utils.randomSecretKey()`): reusing a nonce leaks the private key.
- Do not remove the BIP-340 parity fix (negating `x` when `x*G` has odd y): it is required for x-only pubkey compatibility.
- Length-prefixed hashing in `hashToScalar` is intentional: it prevents domain separation ambiguity when concatenating variable-length fields.
- Key images enforce compressed-point format (02/03 prefix, 33 bytes) to prevent duplicate representations of the same point.
- Any change to signature logic requires corresponding tests. Crypto changes require expert review.
- Work on branches; merge to `main` only when a logical chunk is complete.

## Testing

Vitest is the runner, covering: round-trip sign/verify for both SAG and LSAG,
input validation (ring size, index bounds, duplicates), key image determinism
and duplicate detection, signature tampering detection (modified message,
modified ring, wrong key), and other edge cases. When adding new
functionality, add corresponding tests. PRs touching signature logic require
crypto review.

## Release Notes

- Automated via [forgesworn/anvil](https://github.com/forgesworn/anvil):
  `auto-release.yml` reads conventional commits on push to `main`, bumps the
  version and creates a GitHub Release; `release.yml` then runs the
  pre-publish gates and publishes to npm via OIDC trusted publishing (no
  `NPM_TOKEN` needed).
- `fix:` = patch, `feat:` = minor, `BREAKING CHANGE:` in the commit body = major.
- `chore:`, `docs:`, `refactor:` do not trigger a release.
- Tests must pass before any release-related changes are considered complete.
