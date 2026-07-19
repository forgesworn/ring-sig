// LSAG (Linkable Spontaneous Anonymous Group) Ring Signatures on secp256k1
// Extends SAG with a key image that links signatures by the same signer
// across multiple uses of the same election, enabling double-action detection.

import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { ValidationError } from './errors.js';
import { constantTimeEqual } from './utils.js';
import {
  Point,
  N,
  type ProjectivePoint,
  mod,
  randomScalar,
  scalarToHex,
  hexToScalar,
  hashToScalar,
  hashToPoint,
  safeMultiply,
  scalarEqual,
  G,
} from './utils.js';

export interface LsagSignature {
  keyImage: string;      // compressed point hex (33 bytes / 66 hex chars)
  c0: string;            // starting challenge scalar hex
  responses: string[];   // one scalar hex per ring member
  ring: string[];        // x-only pubkey hex array (internally converted via '02' prefix)
  message: string;       // the signed message
  electionId: string;    // binds key image to this election
  domain?: string;       // domain separator (optional; defaults to 'lsag-v1')
}

/** Maximum number of members in a ring, to prevent denial-of-service via unbounded computation. */
export const MAX_RING_SIZE = 1000;

/** Maximum signed-message length in bytes. The verifier re-hashes the message
 *  once per ring member, so unbounded message length would make verification
 *  cost O(n·len) in attacker-controlled work. 64 KiB is far above any realistic
 *  message while bounding worst-case verification work. */
export const MAX_MESSAGE_BYTES = 65536;

/** Maximum electionId length in bytes. electionId is hashed to a curve point
 *  once per ring member during verification (O(n·len)), so it is bounded too.
 *  An election identifier is small by nature; 512 bytes is generous. */
export const MAX_ELECTION_ID_BYTES = 512;

const DEFAULT_LSAG_DOMAIN = 'lsag-v1';

function validatePubkeyHex(pubkeyHex: string): void {
  if (!/^[0-9a-f]{64}$/i.test(pubkeyHex)) {
    throw new ValidationError(`Invalid x-only public key: expected 64 hex chars, got ${pubkeyHex.length} chars`);
  }
}

function pubkeyToPoint(pubkeyHex: string): ProjectivePoint {
  validatePubkeyHex(pubkeyHex);
  const point = Point.fromHex('02' + pubkeyHex);
  point.assertValidity();
  return point;
}

/**
 * Compute H_p(P || electionId) — the per-member, per-election hash point.
 * P is the compressed (33-byte, 02-prefixed) public key.
 */
function hashPointForMember(pubkeyHex: string, electionId: string): ProjectivePoint {
  const compressedPubkey = hexToBytes('02' + pubkeyHex);
  const electionBytes = utf8ToBytes(electionId);
  const data = new Uint8Array(compressedPubkey.length + electionBytes.length);
  data.set(compressedPubkey);
  data.set(electionBytes, compressedPubkey.length);
  return hashToPoint(data);
}

/**
 * Compute a deterministic key image for a voter in a specific election.
 * I = x * H_p(P || electionId)
 */
export function computeKeyImage(privateKey: string, publicKey: string, electionId: string): string {
  if (typeof privateKey !== 'string') throw new ValidationError('privateKey must be a string');
  if (typeof publicKey !== 'string') throw new ValidationError('publicKey must be a string');
  if (typeof electionId !== 'string' || !electionId) throw new ValidationError('electionId must be a non-empty string');
  publicKey = publicKey.toLowerCase();
  let x = hexToScalar(privateKey);
  // BIP-340 parity fix
  const P = G.multiply(x);
  const pAffine = P.toAffine();
  if (pAffine.y % 2n !== 0n) {
    x = mod(N - x);
  }
  // Verify private key corresponds to the provided public key
  const derivedPub = G.multiply(x);
  const expectedPoint = pubkeyToPoint(publicKey);
  if (!derivedPub.equals(expectedPoint)) {
    throw new ValidationError('Private key does not match the provided public key');
  }
  const Hp = hashPointForMember(publicKey, electionId);
  const I = Hp.multiply(x);
  return bytesToHex(I.toBytes(true));
}

export function hasDuplicateKeyImage(keyImage: string, existingImages: string[]): boolean {
  if (!/^0[23][0-9a-f]{64}$/i.test(keyImage)) {
    throw new ValidationError('Invalid key image format: must be a compressed point (0x02 or 0x03 prefix, 33 bytes hex)');
  }
  const target = hexToBytes(keyImage);
  let found = false;
  for (const img of existingImages) {
    const candidate = hexToBytes(img);
    if (candidate.length === target.length && constantTimeEqual(target, candidate)) {
      found = true;
    }
  }
  return found;
}

function challengeHash(
  domain: Uint8Array,
  msgBytes: Uint8Array,
  ringBytes: Uint8Array,
  L: ProjectivePoint,
  R: ProjectivePoint,
): bigint {
  return hashToScalar(domain, msgBytes, ringBytes, L.toBytes(true), R.toBytes(true));
}

export function lsagSign(
  message: string,
  ring: string[],
  signerIndex: number,
  privateKey: string,
  electionId: string,
  domain: string = DEFAULT_LSAG_DOMAIN,
): LsagSignature {
  if (typeof message !== 'string') throw new ValidationError('message must be a string');
  if (!Array.isArray(ring)) throw new ValidationError('ring must be an array');
  if (typeof privateKey !== 'string') throw new ValidationError('privateKey must be a string');
  if (typeof electionId !== 'string' || !electionId) throw new ValidationError('electionId must be a non-empty string');
  if (utf8ToBytes(electionId).length > MAX_ELECTION_ID_BYTES) throw new ValidationError(`electionId length exceeds maximum of ${MAX_ELECTION_ID_BYTES} bytes`);
  if (ring.length < 2) throw new ValidationError('Ring must have at least 2 members');
  if (ring.length > MAX_RING_SIZE) throw new ValidationError(`Ring size ${ring.length} exceeds maximum of ${MAX_RING_SIZE}`);
  if (!Number.isInteger(signerIndex)) throw new ValidationError('Signer index must be an integer');
  if (signerIndex < 0 || signerIndex >= ring.length) throw new ValidationError('Signer index out of range');
  ring = ring.map(pk => pk.toLowerCase());
  const ringSet = new Set(ring);
  if (ringSet.size !== ring.length) throw new ValidationError('Ring contains duplicate members');

  const n = ring.length;
  const pi = signerIndex;
  let x = hexToScalar(privateKey);
  const msgBytes = utf8ToBytes(message);
  if (msgBytes.length > MAX_MESSAGE_BYTES) throw new ValidationError(`Message length ${msgBytes.length} exceeds maximum of ${MAX_MESSAGE_BYTES} bytes`);
  const domainBytes = utf8ToBytes(domain);
  const ringBytes = concatBytes(...ring.map(k => hexToBytes(k)));
  const ringPoints = ring.map(pubkeyToPoint);

  // BIP-340 parity fix
  const P = G.multiply(x);
  const pAffine = P.toAffine();
  if (pAffine.y % 2n !== 0n) {
    x = mod(N - x);
  }

  // Verify private key corresponds to the claimed ring member
  const derivedPub = G.multiply(x);
  if (!derivedPub.equals(ringPoints[pi])) {
    throw new ValidationError('Private key does not match ring member at signerIndex');
  }

  // Key image: I = x * H_p(P_s || electionId)
  const HpSigner = hashPointForMember(ring[pi], electionId);
  const I = HpSigner.multiply(x);
  const keyImage = bytesToHex(I.toBytes(true));

  const alpha = randomScalar();
  const L_s = G.multiply(alpha);
  const R_s = HpSigner.multiply(alpha);

  const challenges: bigint[] = new Array(n);
  const responses: bigint[] = new Array(n);

  const nextIdx = (pi + 1) % n;
  challenges[nextIdx] = challengeHash(domainBytes, msgBytes, ringBytes, L_s, R_s);

  for (let j = 1; j < n; j++) {
    const i = (pi + j) % n;
    const iNext = (i + 1) % n;
    responses[i] = randomScalar();
    const L_i = safeMultiply(G, responses[i]).add(safeMultiply(ringPoints[i], challenges[i]));
    const HpI = hashPointForMember(ring[i], electionId);
    const R_i = safeMultiply(HpI, responses[i]).add(safeMultiply(I, challenges[i]));
    if (iNext !== nextIdx || j < n - 1) {
      challenges[iNext] = challengeHash(domainBytes, msgBytes, ringBytes, L_i, R_i);
    }
  }

  // KNOWN LIMITATION (see SECURITY.md, "Not constant-time"): `challenges[pi] * x`
  // multiplies the private key x with native BigInt (variable-time) — the only
  // non-constant-time operation touching the secret. A real fix needs a
  // constant-time scalar backend; JS BigInt cannot provide one, so it is documented.
  responses[pi] = mod(alpha - mod(challenges[pi] * x));

  return {
    keyImage,
    c0: scalarToHex(challenges[0]),
    responses: responses.map(scalarToHex),
    ring,
    message,
    electionId,
    ...(domain !== DEFAULT_LSAG_DOMAIN ? { domain } : {}),
  };
}

export function lsagVerify(sig: LsagSignature): boolean {
  try {
    const { keyImage, c0, responses, message, electionId } = sig;
    if (typeof electionId !== 'string' || !electionId) return false;
    if (utf8ToBytes(electionId).length > MAX_ELECTION_ID_BYTES) return false;
    const ring = sig.ring.map(pk => pk.toLowerCase());
    const domain = sig.domain ?? DEFAULT_LSAG_DOMAIN;
    if (ring.length < 2) return false;
    if (ring.length > MAX_RING_SIZE) return false;
    if (responses.length !== ring.length) return false;
    const ringSet = new Set(ring);
    if (ringSet.size !== ring.length) return false;

    // Enforce compressed-point format (02/03 prefix + 32 bytes) to prevent
    // duplicate key images via uncompressed representation of the same point
    if (!/^0[23][0-9a-f]{64}$/i.test(keyImage)) return false;
    const I = Point.fromHex(keyImage);
    I.assertValidity();
    if (I.equals(Point.ZERO)) return false;

    const n = ring.length;
    const msgBytes = utf8ToBytes(message);
    if (msgBytes.length > MAX_MESSAGE_BYTES) return false;
    const domainBytes = utf8ToBytes(domain);
    const ringBytes = concatBytes(...ring.map(k => hexToBytes(k)));
    const ringPoints = ring.map(pubkeyToPoint);

    let c = hexToScalar(c0);

    for (let i = 0; i < n; i++) {
      const s = hexToScalar(responses[i]);
      const L_i = safeMultiply(G, s).add(safeMultiply(ringPoints[i], c));
      const HpI = hashPointForMember(ring[i], electionId);
      const R_i = safeMultiply(HpI, s).add(safeMultiply(I, c));
      c = challengeHash(domainBytes, msgBytes, ringBytes, L_i, R_i);
    }

    return scalarEqual(c, hexToScalar(c0));
  } catch {
    return false;
  }
}
