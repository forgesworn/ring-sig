# Contributing

## Setup

```bash
git clone https://github.com/forgesworn/@forgesworn/ring-sig.git
cd @forgesworn/ring-sig
npm install
npm test
```

## Development Workflow

```bash
npm run build      # Compile TypeScript → dist/
npm test           # Run test suite (vitest)
npm run typecheck  # Type-check without emitting (tsc --noEmit)
```

Always run `npm run typecheck` and `npm test` before committing.

## Branch Strategy

This repository uses **semantic-release** on `main` — every push to `main` automatically publishes a new npm version based on commit messages.

- **Always work on a branch** (never commit directly to `main`).
- Merge or squash to `main` only when a logical chunk of work is complete.
- This produces one clean release instead of many incremental versions.

## Commit Conventions

Commit messages follow the `type: description` format. The type determines the version bump:

| Type | Version bump | Example |
|------|-------------|---------|
| `feat:` | minor | `feat: add batch verification` |
| `fix:` | patch | `fix: reject identity point as key image` |
| `docs:` | none | `docs: clarify domain separator usage` |
| `refactor:` | none | `refactor: extract challenge hash helper` |
| `test:` | none | `test: add LSAG tampering detection cases` |
| `chore:` | none | `chore: update dev dependencies` |

Use `BREAKING CHANGE:` in the commit body (or `feat!:` / `fix!:`) for major version bumps.

## Crypto Review Policy

**PRs that touch signature logic require careful review.** This includes:

- Anything in `src/sag.ts`, `src/lsag.ts`, or `src/utils.ts`
- Changes to domain separators, hashing, nonce generation, or scalar arithmetic
- Changes to constant-time comparison functions

If you are unsure whether a change affects cryptographic security, flag it for review. The domain separators (`'sag-v1'`, `'lsag-v1'`, `'secp256k1-hash-to-point-v1'`) are protocol constants — changing them breaks all existing signatures.

## Style

- **British English** in all prose — colour, initialise, behaviour, licence.
- **ESM-only** — all imports use `.js` extensions.
- Keep test coverage high. Every new function or code path should have corresponding tests.

## Reporting Issues

Open an issue on GitHub. If the issue involves a potential security vulnerability, please report it privately rather than in a public issue.
