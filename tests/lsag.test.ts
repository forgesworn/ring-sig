import { describe, it, expect } from 'vitest';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { MAX_RING_SIZE, computeKeyImage, lsagSign, lsagVerify, hasDuplicateKeyImage } from '../src/lsag.js';
import { ValidationError } from '../src/errors.js';

function generateKeyPair(): { privateKey: string; publicKey: string } {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = schnorr.getPublicKey(priv);
  return { privateKey: bytesToHex(priv), publicKey: bytesToHex(pub) };
}

describe('LSAG', () => {
  const signer = generateKeyPair();
  const other1 = generateKeyPair();
  const other2 = generateKeyPair();
  const ring = [signer.publicKey, other1.publicKey, other2.publicKey];
  const electionId = 'test-election-2026';

  describe('computeKeyImage', () => {
    it('is deterministic for same inputs', () => {
      const img1 = computeKeyImage(signer.privateKey, signer.publicKey, electionId);
      const img2 = computeKeyImage(signer.privateKey, signer.publicKey, electionId);
      expect(img1).toBe(img2);
      expect(img1).toMatch(/^[0-9a-f]{66}$/);
    });

    it('differs across elections', () => {
      const img1 = computeKeyImage(signer.privateKey, signer.publicKey, 'election-A');
      const img2 = computeKeyImage(signer.privateKey, signer.publicKey, 'election-B');
      expect(img1).not.toBe(img2);
    });

    it('differs across signers', () => {
      const img1 = computeKeyImage(signer.privateKey, signer.publicKey, electionId);
      const img2 = computeKeyImage(other1.privateKey, other1.publicKey, electionId);
      expect(img1).not.toBe(img2);
    });
  });

  describe('hasDuplicateKeyImage', () => {
    it('returns true when key image exists', () => {
      const img = computeKeyImage(signer.privateKey, signer.publicKey, electionId);
      expect(hasDuplicateKeyImage(img, [img])).toBe(true);
    });

    it('returns false when key image is new', () => {
      const img = computeKeyImage(signer.privateKey, signer.publicKey, electionId);
      expect(hasDuplicateKeyImage(img, [])).toBe(false);
    });
  });

  describe('lsagSign', () => {
    it('produces a valid signature structure', () => {
      const sig = lsagSign('test message', ring, 0, signer.privateKey, electionId);
      expect(sig.keyImage).toMatch(/^[0-9a-f]{66}$/);
      expect(sig.c0).toMatch(/^[0-9a-f]{64}$/);
      expect(sig.responses).toHaveLength(3);
      expect(sig.ring).toEqual(ring);
      expect(sig.message).toBe('test message');
      expect(sig.electionId).toBe(electionId);
    });

    it('rejects ring size < 2', () => {
      expect(() => lsagSign('msg', [signer.publicKey], 0, signer.privateKey, electionId))
        .toThrow('Ring must have at least 2 members');
    });

    it('rejects ring size exceeding MAX_RING_SIZE in lsagSign', () => {
      const dummyKey = 'a'.repeat(64);
      const oversizedRing = Array(MAX_RING_SIZE + 1).fill(dummyKey);
      expect(() => lsagSign('msg', oversizedRing, 0, 'b'.repeat(64), electionId)).toThrow(
        `Ring size ${MAX_RING_SIZE + 1} exceeds maximum of ${MAX_RING_SIZE}`
      );
    });

    it('rejects signer index out of range', () => {
      expect(() => lsagSign('msg', ring, 5, signer.privateKey, electionId))
        .toThrow('Signer index out of range');
    });

    it('rejects malformed pubkey hex', () => {
      expect(() => lsagSign('msg', ['not-a-key', other1.publicKey], 0, signer.privateKey, electionId))
        .toThrow(); // rejects via validatePubkeyHex or hexToBytes
    });
  });

  describe('lsagVerify', () => {
    it('accepts a valid signature', () => {
      const sig = lsagSign('verify me', ring, 0, signer.privateKey, electionId);
      expect(lsagVerify(sig)).toBe(true);
    });

    it('accepts signature from any ring position', () => {
      const ring2 = [other1.publicKey, signer.publicKey, other2.publicKey];
      const sig = lsagSign('position test', ring2, 1, signer.privateKey, electionId);
      expect(lsagVerify(sig)).toBe(true);
    });

    it('rejects tampered message', () => {
      const sig = lsagSign('original', ring, 0, signer.privateKey, electionId);
      sig.message = 'tampered';
      expect(lsagVerify(sig)).toBe(false);
    });

    it('rejects tampered response', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const r = BigInt('0x' + sig.responses[0]);
      sig.responses[0] = (r ^ 1n).toString(16).padStart(64, '0');
      expect(lsagVerify(sig)).toBe(false);
    });

    it('rejects swapped ring member', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const extra = generateKeyPair();
      sig.ring = [extra.publicKey, ...sig.ring.slice(1)];
      expect(lsagVerify(sig)).toBe(false);
    });

    it('rejects wrong key image', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const wrongImage = computeKeyImage(signer.privateKey, signer.publicKey, 'other-election');
      sig.keyImage = wrongImage;
      expect(lsagVerify(sig)).toBe(false);
    });

    it('rejects identity point as key image', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      sig.keyImage = '00'.repeat(33);
      expect(lsagVerify(sig)).toBe(false);
    });

    it('rejects ring size exceeding MAX_RING_SIZE in lsagVerify', () => {
      const dummyKey = 'a'.repeat(64);
      const oversizedRing = Array(MAX_RING_SIZE + 1).fill(dummyKey);
      const sig = {
        keyImage: '02' + 'a'.repeat(64),
        c0: 'a'.repeat(64),
        responses: Array(MAX_RING_SIZE + 1).fill('b'.repeat(64)),
        ring: oversizedRing,
        message: 'test',
        electionId,
      };
      expect(lsagVerify(sig)).toBe(false);
    });

    it('ring order matters', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const reversed = [...ring].reverse();
      sig.ring = reversed;
      expect(lsagVerify(sig)).toBe(false);
    });

    it('key image matches computeKeyImage output', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const expected = computeKeyImage(signer.privateKey, signer.publicKey, electionId);
      expect(sig.keyImage).toBe(expected);
    });
  });

  describe('custom domain', () => {
    it('signs and verifies with a custom domain', () => {
      const sig = lsagSign('domain test', ring, 0, signer.privateKey, electionId, 'custom-lsag-v1');
      expect(sig.domain).toBe('custom-lsag-v1');
      expect(lsagVerify(sig)).toBe(true);
    });

    it('omits domain field when using default', () => {
      const sig = lsagSign('default domain', ring, 0, signer.privateKey, electionId);
      expect(sig.domain).toBeUndefined();
      expect(lsagVerify(sig)).toBe(true);
    });

    it('cross-domain incompatibility: domain A sig fails with domain B', () => {
      const sig = lsagSign('cross-domain', ring, 0, signer.privateKey, electionId, 'domain-A');
      expect(lsagVerify(sig)).toBe(true);
      // Tamper domain to B — must fail
      sig.domain = 'domain-B';
      expect(lsagVerify(sig)).toBe(false);
    });
  });

  describe('input validation', () => {
    it('rejects non-integer signerIndex (NaN)', () => {
      expect(() => lsagSign('test', ring, NaN, signer.privateKey, electionId))
        .toThrow(ValidationError);
    });

    it('rejects non-integer signerIndex (Infinity)', () => {
      expect(() => lsagSign('test', ring, Infinity, signer.privateKey, electionId))
        .toThrow(ValidationError);
    });

    it('rejects non-integer signerIndex (float)', () => {
      expect(() => lsagSign('test', ring, 0.5, signer.privateKey, electionId))
        .toThrow(ValidationError);
    });

    it('rejects mismatched private key', () => {
      // Use other1's private key but claim to be signer (index 0)
      expect(() => lsagSign('test', ring, 0, other1.privateKey, electionId))
        .toThrow(ValidationError);
    });
  });
});
