// Shared secp256k1 utilities for sag.ts and lsag.ts.

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils';
import { ValidationError, CryptoError } from './errors.js';

export const Point = secp256k1.ProjectivePoint;
export const N = secp256k1.CURVE.n;
export type ProjectivePoint = typeof Point.BASE;

/** Constant-time comparison of two equal-length Uint8Arrays.
 *  Always compares all bytes; does not short-circuit on content.
 *
 *  NOTE: The length check IS an early return (not constant-time w.r.t. length),
 *  but all callers compare fixed-size buffers (32-byte scalars), so this is safe. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) { diff |= a[i] ^ b[i]; }
  return diff === 0;
}

/** Modular arithmetic helper — defaults to curve order N */
export function mod(a: bigint, m: bigint = N): bigint {
  const result = a % m;
  return result >= 0n ? result : result + m;
}

/** Generate a random scalar in [1, N-1] (rejection sampling if mod reduces to 0) */
export function randomScalar(): bigint {
  let s: bigint;
  do {
    const bytes = secp256k1.utils.randomPrivateKey();
    s = mod(BigInt('0x' + bytesToHex(bytes)));
  } while (s === 0n);
  return s;
}

/** Convert a scalar bigint to 32-byte hex */
export function scalarToHex(s: bigint): string {
  return s.toString(16).padStart(64, '0');
}

/** Convert hex to bigint scalar, validated and reduced mod N */
export function hexToScalar(hex: string): bigint {
  if (!/^[0-9a-f]{1,64}$/i.test(hex)) throw new ValidationError('Invalid scalar hex');
  return mod(BigInt('0x' + hex));
}

/** Constant-time equality check for two scalars (compared as 32-byte arrays) */
export function scalarEqual(a: bigint, b: bigint): boolean {
  const aBuf = hexToBytes(mod(a).toString(16).padStart(64, '0'));
  const bBuf = hexToBytes(mod(b).toString(16).padStart(64, '0'));
  return constantTimeEqual(aBuf, bBuf);
}

/** Hash to scalar: SHA-256 of concatenated data, reduced mod N.
 *
 *  NOTE: SHA-256 produces 256 bits and N is ~2^256, so the modular reduction
 *  introduces a negligible bias (~2^-128). This is acceptable for Fiat-Shamir
 *  challenges. A wider hash (e.g. SHA-512) would eliminate the bias entirely
 *  per RFC 9380 hash-to-field, but is not required at this security level. */
export function hashToScalar(domain: Uint8Array, ...parts: Uint8Array[]): bigint {
  const data = concatBytes(domain, ...parts);
  const h = sha256(data);
  return mod(BigInt('0x' + bytesToHex(h)));
}

/** Safe scalar multiplication — handles 0n (which noble/curves rejects) */
export function safeMultiply(point: ProjectivePoint, scalar: bigint): ProjectivePoint {
  const s = mod(scalar);
  if (s === 0n) return Point.ZERO;
  return point.multiply(s);
}

// --- Generator Points ---

/** Generator G: standard secp256k1 base point */
export const G = Point.BASE;

/**
 * Hash arbitrary data to a valid secp256k1 curve point using try-and-increment.
 * Domain-separated with 'secp256k1-hash-to-point-v1'.
 */
export function hashToPoint(data: Uint8Array): ProjectivePoint {
  const prefix = utf8ToBytes('secp256k1-hash-to-point-v1');
  for (let i = 0; i < 256; i++) {
    const buf = new Uint8Array(prefix.length + data.length + 1);
    buf.set(prefix);
    buf.set(data, prefix.length);
    buf[prefix.length + data.length] = i;
    const h = sha256(buf);
    const hex = '02' + bytesToHex(h);
    try {
      const point = Point.fromHex(hex);
      point.assertValidity();
      return point;
    } catch {
      continue;
    }
  }
  throw new CryptoError('Failed to hash to curve point');
}

/**
 * Generator H: nothing-up-my-sleeve second generator for Pedersen commitments.
 * Created by hashing to a curve point — nobody knows log_G(H).
 */
function createGeneratorH(): ProjectivePoint {
  const seed = utf8ToBytes('secp256k1-pedersen-H-v1');
  for (let i = 0; i < 256; i++) {
    const buf = new Uint8Array(seed.length + 1);
    buf.set(seed);
    buf[seed.length] = i;
    const h = sha256(buf);
    const hex = '02' + bytesToHex(h);
    try {
      const point = Point.fromHex(hex);
      point.assertValidity();
      return point;
    } catch {
      continue;
    }
  }
  throw new CryptoError('Failed to generate H point');
}

export const H = createGeneratorH();
