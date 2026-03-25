# [2.0.0](https://github.com/forgesworn/ring-sig/compare/v1.0.2...v2.0.0) (2026-03-25)


* feat!: upgrade to @noble/curves v2 and @noble/hashes v2 ([8d9346f](https://github.com/forgesworn/ring-sig/commit/8d9346fec0353b8a765c425a032e365e8a2be147))


### BREAKING CHANGES

* @noble/curves upgraded from v1 to v2. Import paths now require .js suffix if consuming from source. Published dist/ is unaffected.

## [1.0.2](https://github.com/forgesworn/ring-sig/compare/v1.0.1...v1.0.2) (2026-03-20)


### Bug Fixes

* correct copyright to ForgeSworn ([74d4aa3](https://github.com/forgesworn/ring-sig/commit/74d4aa3c590cfab412cf25f394df4d40f702e00d))

## [1.0.1](https://github.com/forgesworn/ring-sig/compare/v1.0.0...v1.0.1) (2026-03-18)


### Bug Fixes

* correct broken URLs in SECURITY.md and CONTRIBUTING.md ([803beaa](https://github.com/forgesworn/ring-sig/commit/803beaaba20dd9311817bc9e60e5673b2515ca6c))
* harden input validation — case-normalise ring, type guards, key pair check ([c2ce9ce](https://github.com/forgesworn/ring-sig/commit/c2ce9ce71003edf5f846f8359e51bac3e1d8fad9))
* pin GitHub Actions to commit SHAs for supply chain integrity ([3c3688a](https://github.com/forgesworn/ring-sig/commit/3c3688a2938a01dd35101f011806e7cd9a538241))
* regenerate lockfile to match renamed package ([0b72e48](https://github.com/forgesworn/ring-sig/commit/0b72e48613463dbe45dc840cf063ec77d42ff9cb))
* resolve merge conflict — correct package name with released version ([b3c1a4d](https://github.com/forgesworn/ring-sig/commit/b3c1a4deaaba723d65c647c89c68474e24f38c62))

# 1.0.0 (2026-03-18)


### Bug Fixes

* security audit — domain handling, input validation, length-prefixed hashing ([b5815ce](https://github.com/forgesworn/ring-sig/commit/b5815cee52d0c1dc8ac0fec9c076786ec76366f5))


### Features

* add crypto utilities and error classes ([910ec23](https://github.com/forgesworn/ring-sig/commit/910ec23456121b6a871a18a1b9caa3917a3d4a63))
* add LSAG linkable ring signatures with tests ([170ac17](https://github.com/forgesworn/ring-sig/commit/170ac17f82c5b98de46a8d23578857a76f79dcc1))
* add SAG ring signatures with tests ([bf25cda](https://github.com/forgesworn/ring-sig/commit/bf25cda0a82d7112832755b64e9ada34b9bf3d69))
* expose public API ([8a73a6b](https://github.com/forgesworn/ring-sig/commit/8a73a6b2ce7cfe3869d9918cd4c98a92177b8e85))
