// SAG Ring Signatures on secp256k1
// Proves "one of N public keys signed this message" without revealing which one.

import { utf8ToBytes, hexToBytes, concatBytes } from '@noble/hashes/utils';
import {
  Point,
  N,
  type ProjectivePoint,
  mod,
  randomScalar,
  scalarToHex,
  hexToScalar,
  hashToScalar,
  safeMultiply,
  scalarEqual,
} from './utils.js';
import { ValidationError } from './errors.js';

/** Maximum number of members in a ring, to prevent denial-of-service via unbounded computation. */
export const MAX_RING_SIZE = 1000;

const DEFAULT_SAG_DOMAIN = 'sag-v1';

/** A ring signature: starting challenge + response scalars */
export interface RingSignature {
  /** The ring of public keys (x-only hex, 32 bytes each) */
  ring: string[];
  /** Starting challenge c_0 */
  c0: string;
  /** Response scalars s_0 ... s_{n-1} */
  responses: string[];
  /** The signed message hash */
  message: string;
  /** Domain separator (optional; defaults to 'sag-v1') */
  domain?: string;
}

/** Validate an x-only public key is exactly 64 hex characters. */
function validatePubkeyHex(pubkeyHex: string): void {
  if (!/^[0-9a-f]{64}$/i.test(pubkeyHex)) {
    throw new ValidationError(`Invalid x-only public key: expected 64 hex chars, got ${pubkeyHex.length} chars`);
  }
}

/** Load a public key from x-only hex (32 bytes) to a curve point.
 *  Assumes even y-coordinate (BIP-340 convention). */
function pubkeyToPoint(pubkeyHex: string): ProjectivePoint {
  validatePubkeyHex(pubkeyHex);
  // x-only pubkey: prepend 02 for even y
  const point = Point.fromHex('02' + pubkeyHex);
  point.assertValidity();
  return point;
}

/**
 * Sign a message with a ring signature.
 *
 * @param message - The message to sign (will be hashed)
 * @param ring - Array of x-only public keys (hex) forming the anonymity set
 * @param signerIndex - Index of the actual signer in the ring
 * @param privateKey - Signer's private key (hex)
 * @param domain - Optional domain separator (defaults to 'sag-v1')
 * @returns A ring signature
 */
export function ringSign(
  message: string,
  ring: string[],
  signerIndex: number,
  privateKey: string,
  domain: string = DEFAULT_SAG_DOMAIN
): RingSignature {
  if (ring.length < 2) throw new ValidationError('Ring must have at least 2 members');
  if (ring.length > MAX_RING_SIZE) throw new ValidationError(`Ring size ${ring.length} exceeds maximum of ${MAX_RING_SIZE}`);
  if (signerIndex < 0 || signerIndex >= ring.length) throw new ValidationError('Signer index out of range');
  const ringSet = new Set(ring);
  if (ringSet.size !== ring.length) throw new ValidationError('Ring contains duplicate members');

  const n = ring.length;
  const pi = signerIndex;
  let x = hexToScalar(privateKey);
  const msgBytes = utf8ToBytes(message);
  const domainBytes = utf8ToBytes(domain);

  // Load ring public keys as curve points
  const ringPoints = ring.map(pubkeyToPoint);

  // BIP-340 parity fix: pubkeyToPoint always uses even y ('02' prefix).
  // If x*G has odd y, negate x so that x*G matches the even-y point.
  const P = Point.BASE.multiply(x);
  const pAffine = P.toAffine();
  if (pAffine.y % 2n !== 0n) {
    x = mod(N - x);
  }

  // Step 1: Random nonce
  const k = randomScalar();
  const kG = Point.BASE.multiply(k);

  // Step 2: Compute c_{pi+1}
  const challenges: bigint[] = new Array(n);
  const responses: bigint[] = new Array(n);

  const nextIdx = (pi + 1) % n;
  challenges[nextIdx] = hashToScalar(
    domainBytes,
    msgBytes,
    concatBytes(...ring.map(k => hexToBytes(k))),
    kG.toRawBytes(true)
  );

  // Step 3: For i = pi+1, pi+2, ..., pi-1 (mod n): fill in random responses and compute challenges
  for (let j = 1; j < n; j++) {
    const i = (pi + j) % n;
    const iNext = (i + 1) % n;

    responses[i] = randomScalar();

    // R_i = s_i * G + c_i * P_i
    const sG = safeMultiply(Point.BASE, responses[i]);
    const cP = safeMultiply(ringPoints[i], challenges[i]);
    const R = sG.add(cP);

    if (iNext !== nextIdx || j < n - 1) {
      challenges[iNext] = hashToScalar(
        domainBytes,
        msgBytes,
        concatBytes(...ring.map(k => hexToBytes(k))),
        R.toRawBytes(true)
      );
    }
  }

  // Step 4: Compute s_pi = k - c_pi * x (mod N)
  responses[pi] = mod(k - mod(challenges[pi] * x));

  return {
    ring,
    c0: scalarToHex(challenges[0]),
    responses: responses.map(scalarToHex),
    message,
  };
}

/**
 * Verify a ring signature.
 *
 * @param sig - The ring signature to verify
 * @returns true if the signature is valid
 */
export function ringVerify(sig: RingSignature): boolean {
  try {
    const { ring, c0, responses, message } = sig;
    const domain = sig.domain ?? DEFAULT_SAG_DOMAIN;
    if (ring.length < 2) return false;
    if (ring.length > MAX_RING_SIZE) return false;
    if (responses.length !== ring.length) return false;
    const ringSet = new Set(ring);
    if (ringSet.size !== ring.length) return false;

    const n = ring.length;
    const msgBytes = utf8ToBytes(message);
    const domainBytes = utf8ToBytes(domain);
    const ringPoints = ring.map(pubkeyToPoint);

    let c = hexToScalar(c0);

    for (let i = 0; i < n; i++) {
      const s = hexToScalar(responses[i]);

      // R_i = s_i * G + c_i * P_i
      const sG = safeMultiply(Point.BASE, s);
      const cP = safeMultiply(ringPoints[i], c);
      const R = sG.add(cP);

      // c_{i+1} = H(domain, msg, ring, R_i)
      c = hashToScalar(
        domainBytes,
        msgBytes,
        concatBytes(...ring.map(k => hexToBytes(k))),
        R.toRawBytes(true)
      );
    }

    // Check: computed c_n wraps around to c_0
    return scalarEqual(c, hexToScalar(c0));
  } catch {
    return false;
  }
}
