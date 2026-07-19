import { describe, it, expect } from 'vitest';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MAX_RING_SIZE, MAX_MESSAGE_BYTES, MAX_ELECTION_ID_BYTES, computeKeyImage, lsagSign, lsagVerify, hasDuplicateKeyImage } from '../src/lsag.js';
import { ValidationError } from '../src/errors.js';

function generateKeyPair(): { privateKey: string; publicKey: string } {
  const priv = secp256k1.utils.randomSecretKey();
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

  describe('encoding malleability (canonical scalar form)', () => {
    it('rejects a re-encoded (upper-cased) twin of a valid signature', () => {
      const sig = lsagSign('malleability', ring, 0, signer.privateKey, electionId);
      expect(lsagVerify(sig)).toBe(true);

      const fields = [sig.c0, ...sig.responses];
      const idx = fields.findIndex((f) => /[a-f]/.test(f));
      expect(idx).toBeGreaterThanOrEqual(0);
      const twin = { ...sig, responses: [...sig.responses] };
      if (idx === 0) twin.c0 = sig.c0.toUpperCase();
      else twin.responses[idx - 1] = sig.responses[idx - 1].toUpperCase();

      expect(lsagVerify(twin)).toBe(false);
    });
  });

  describe('length caps (DoS bound)', () => {
    it('signs and verifies a message at exactly MAX_MESSAGE_BYTES', () => {
      const message = 'a'.repeat(MAX_MESSAGE_BYTES);
      const sig = lsagSign(message, ring, 0, signer.privateKey, electionId);
      expect(lsagVerify(sig)).toBe(true);
    });

    it('rejects an over-length message in lsagSign', () => {
      const message = 'a'.repeat(MAX_MESSAGE_BYTES + 1);
      expect(() => lsagSign(message, ring, 0, signer.privateKey, electionId))
        .toThrow(`exceeds maximum of ${MAX_MESSAGE_BYTES} bytes`);
    });

    it('rejects an over-length message in lsagVerify', () => {
      const sig = lsagSign('short', ring, 0, signer.privateKey, electionId);
      sig.message = 'a'.repeat(MAX_MESSAGE_BYTES + 1);
      expect(lsagVerify(sig)).toBe(false);
    });

    it('signs and verifies an electionId at exactly MAX_ELECTION_ID_BYTES', () => {
      const bigElection = 'e'.repeat(MAX_ELECTION_ID_BYTES);
      const sig = lsagSign('test', ring, 0, signer.privateKey, bigElection);
      expect(lsagVerify(sig)).toBe(true);
    });

    it('rejects an over-length electionId in lsagSign', () => {
      const bigElection = 'e'.repeat(MAX_ELECTION_ID_BYTES + 1);
      expect(() => lsagSign('test', ring, 0, signer.privateKey, bigElection))
        .toThrow(`exceeds maximum of ${MAX_ELECTION_ID_BYTES} bytes`);
    });

    it('rejects an over-length electionId in lsagVerify', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      sig.electionId = 'e'.repeat(MAX_ELECTION_ID_BYTES + 1);
      expect(lsagVerify(sig)).toBe(false);
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

    it('rejects non-string message', () => {
      expect(() => lsagSign(123 as any, ring, 0, signer.privateKey, electionId))
        .toThrow(ValidationError);
    });

    it('rejects non-array ring', () => {
      expect(() => lsagSign('test', 'not-an-array' as any, 0, signer.privateKey, electionId))
        .toThrow(ValidationError);
    });

    it('rejects non-string privateKey', () => {
      expect(() => lsagSign('test', ring, 0, 123 as any, electionId))
        .toThrow(ValidationError);
    });

    it('rejects empty electionId', () => {
      expect(() => lsagSign('test', ring, 0, signer.privateKey, ''))
        .toThrow(ValidationError);
    });

    it('detects mixed-case hex duplicate ring members', () => {
      const upper = ring[0].toUpperCase();
      const dupeRing = [ring[0], upper, ring[2]];
      expect(() => lsagSign('test', dupeRing, 0, signer.privateKey, electionId))
        .toThrow('duplicate');
    });

    it('handles uppercase hex pubkeys correctly', () => {
      const upperRing = ring.map(pk => pk.toUpperCase());
      const sig = lsagSign('upper test', upperRing, 0, signer.privateKey, electionId);
      // Ring is normalised to lowercase in the returned signature
      expect(sig.ring).toEqual(ring.map(pk => pk.toLowerCase()));
      expect(lsagVerify(sig)).toBe(true);
    });

    it('verifies a signature whose stored ring has uppercase keys', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      // Simulate deserialisation with uppercase ring
      const upperSig = { ...sig, ring: sig.ring.map(pk => pk.toUpperCase()) };
      expect(lsagVerify(upperSig)).toBe(true);
    });
  });

  describe('computeKeyImage validation', () => {
    it('rejects mismatched private/public key pair', () => {
      expect(() => computeKeyImage(other1.privateKey, signer.publicKey, electionId))
        .toThrow(ValidationError);
    });

    it('rejects empty electionId', () => {
      expect(() => computeKeyImage(signer.privateKey, signer.publicKey, ''))
        .toThrow(ValidationError);
    });

    it('rejects non-string inputs', () => {
      expect(() => computeKeyImage(123 as any, signer.publicKey, electionId))
        .toThrow(ValidationError);
      expect(() => computeKeyImage(signer.privateKey, 123 as any, electionId))
        .toThrow(ValidationError);
      expect(() => computeKeyImage(signer.privateKey, signer.publicKey, 123 as any))
        .toThrow(ValidationError);
    });
  });

  describe('lsagVerify edge cases', () => {
    it('rejects signature with missing electionId', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const bad = { ...sig, electionId: undefined } as any;
      expect(lsagVerify(bad)).toBe(false);
    });

    it('rejects signature with empty electionId', () => {
      const sig = lsagSign('test', ring, 0, signer.privateKey, electionId);
      const bad = { ...sig, electionId: '' };
      expect(lsagVerify(bad)).toBe(false);
    });
  });
});
