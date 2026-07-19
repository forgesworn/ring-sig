import { describe, it, expect } from 'vitest';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  MAX_RING_SIZE,
  MAX_MESSAGE_BYTES,
  ringSign,
  ringVerify,
} from '../src/sag.js';
import { ValidationError } from '../src/errors.js';

function generateKeyPair(): { privateKey: string; publicKey: string } {
  const priv = secp256k1.utils.randomSecretKey();
  const pub = schnorr.getPublicKey(priv);
  return { privateKey: bytesToHex(priv), publicKey: bytesToHex(pub) };
}

describe('ring-signature (SAG)', () => {
  function makeRing(size: number) {
    const keys = Array.from({ length: size }, () => generateKeyPair());
    return {
      keys,
      pubkeys: keys.map((k) => k.publicKey),
    };
  }

  describe('ringSign / ringVerify', () => {
    it('signs and verifies with ring size 2', () => {
      const { keys, pubkeys } = makeRing(2);
      const sig = ringSign('hello', pubkeys, 0, keys[0].privateKey);
      expect(ringVerify(sig)).toBe(true);
    });

    it('signs and verifies with ring size 5', () => {
      const { keys, pubkeys } = makeRing(5);
      const sig = ringSign('test message', pubkeys, 3, keys[3].privateKey);
      expect(ringVerify(sig)).toBe(true);
    });

    it('signs and verifies with ring size 10', () => {
      const { keys, pubkeys } = makeRing(10);
      const sig = ringSign('larger ring', pubkeys, 7, keys[7].privateKey);
      expect(ringVerify(sig)).toBe(true);
    });

    it('any position in the ring can be the signer', () => {
      const { keys, pubkeys } = makeRing(5);
      for (let i = 0; i < 5; i++) {
        const sig = ringSign(`position-${i}`, pubkeys, i, keys[i].privateKey);
        expect(ringVerify(sig)).toBe(true);
      }
    });

    it('rejects tampered message', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('original', pubkeys, 1, keys[1].privateKey);
      sig.message = 'tampered';
      expect(ringVerify(sig)).toBe(false);
    });

    it('rejects tampered responses', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('test', pubkeys, 0, keys[0].privateKey);
      // XOR the first byte to guarantee a different value
      const r = BigInt('0x' + sig.responses[1]);
      sig.responses[1] = (r ^ 1n).toString(16).padStart(64, '0');
      expect(ringVerify(sig)).toBe(false);
    });

    it('rejects wrong ring member', () => {
      const { keys, pubkeys } = makeRing(3);
      const outsider = generateKeyPair();
      // Replace one ring member
      const modifiedRing = [...pubkeys];
      modifiedRing[2] = outsider.publicKey;

      const sig = ringSign('test', pubkeys, 0, keys[0].privateKey);
      sig.ring = modifiedRing;
      expect(ringVerify(sig)).toBe(false);
    });

    it('rejects ring size 1', () => {
      const keys = generateKeyPair();
      expect(() => ringSign('test', [keys.publicKey], 0, keys.privateKey)).toThrow('at least 2');
    });

    it('rejects ring size exceeding MAX_RING_SIZE in ringSign', () => {
      const dummyKey = 'a'.repeat(64);
      const oversizedRing = Array(MAX_RING_SIZE + 1).fill(dummyKey);
      expect(() => ringSign('test', oversizedRing, 0, 'b'.repeat(64))).toThrow(
        `Ring size ${MAX_RING_SIZE + 1} exceeds maximum of ${MAX_RING_SIZE}`
      );
    });

    it('rejects ring size exceeding MAX_RING_SIZE in ringVerify', () => {
      const dummyKey = 'a'.repeat(64);
      const oversizedRing = Array(MAX_RING_SIZE + 1).fill(dummyKey);
      const sig = {
        ring: oversizedRing,
        c0: 'a'.repeat(64),
        responses: Array(MAX_RING_SIZE + 1).fill('b'.repeat(64)),
        message: 'test',
      };
      expect(ringVerify(sig)).toBe(false);
    });
  });

  describe('custom domain', () => {
    it('signs and verifies with a custom domain', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('domain test', pubkeys, 1, keys[1].privateKey, 'custom-domain-v1');
      expect(sig.domain).toBe('custom-domain-v1');
      expect(ringVerify(sig)).toBe(true);
    });

    it('omits domain field when using default', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('default domain', pubkeys, 0, keys[0].privateKey);
      expect(sig.domain).toBeUndefined();
      expect(ringVerify(sig)).toBe(true);
    });

    it('cross-domain incompatibility: domain A sig fails with domain B', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('cross-domain', pubkeys, 0, keys[0].privateKey, 'domain-A');
      expect(ringVerify(sig)).toBe(true);
      // Tamper domain to B — must fail
      sig.domain = 'domain-B';
      expect(ringVerify(sig)).toBe(false);
    });
  });

  describe('encoding malleability (canonical scalar form)', () => {
    it('rejects a re-encoded (upper-cased) twin of a valid signature', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('malleability', pubkeys, 0, keys[0].privateKey);
      expect(ringVerify(sig)).toBe(true);

      // Upper-case the first scalar field that contains a hex letter — the same
      // integer, a different encoding. A malleable verifier would accept it.
      const fields = [sig.c0, ...sig.responses];
      const idx = fields.findIndex((f) => /[a-f]/.test(f));
      expect(idx).toBeGreaterThanOrEqual(0); // essentially always true for random scalars
      const twin = { ...sig, responses: [...sig.responses] };
      if (idx === 0) twin.c0 = sig.c0.toUpperCase();
      else twin.responses[idx - 1] = sig.responses[idx - 1].toUpperCase();

      expect(ringVerify(twin)).toBe(false);
    });

    it('rejects a stripped leading-zero-nibble twin of c0', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('strip', pubkeys, 0, keys[0].privateKey);
      // A 63-char encoding of the same value must be rejected as non-canonical.
      const shortC0 = BigInt('0x' + sig.c0).toString(16); // no padStart -> may drop leading zeros
      const twin = { ...sig, c0: shortC0 };
      if (shortC0.length !== 64) {
        expect(ringVerify(twin)).toBe(false);
      }
      // The canonical original always verifies.
      expect(ringVerify(sig)).toBe(true);
    });
  });

  describe('message length cap (DoS bound)', () => {
    it('signs and verifies a message at exactly MAX_MESSAGE_BYTES', () => {
      const { keys, pubkeys } = makeRing(3);
      const message = 'a'.repeat(MAX_MESSAGE_BYTES);
      const sig = ringSign(message, pubkeys, 0, keys[0].privateKey);
      expect(ringVerify(sig)).toBe(true);
    });

    it('rejects an over-length message in ringSign', () => {
      const { keys, pubkeys } = makeRing(3);
      const message = 'a'.repeat(MAX_MESSAGE_BYTES + 1);
      expect(() => ringSign(message, pubkeys, 0, keys[0].privateKey))
        .toThrow(`exceeds maximum of ${MAX_MESSAGE_BYTES} bytes`);
    });

    it('rejects an over-length message in ringVerify', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('short', pubkeys, 0, keys[0].privateKey);
      sig.message = 'a'.repeat(MAX_MESSAGE_BYTES + 1);
      expect(ringVerify(sig)).toBe(false);
    });
  });

  describe('input validation', () => {
    it('rejects non-integer signerIndex (NaN)', () => {
      const { keys, pubkeys } = makeRing(3);
      expect(() => ringSign('test', pubkeys, NaN, keys[0].privateKey))
        .toThrow(ValidationError);
    });

    it('rejects non-integer signerIndex (Infinity)', () => {
      const { keys, pubkeys } = makeRing(3);
      expect(() => ringSign('test', pubkeys, Infinity, keys[0].privateKey))
        .toThrow(ValidationError);
    });

    it('rejects non-integer signerIndex (float)', () => {
      const { keys, pubkeys } = makeRing(3);
      expect(() => ringSign('test', pubkeys, 0.5, keys[0].privateKey))
        .toThrow(ValidationError);
    });

    it('rejects mismatched private key', () => {
      const { keys, pubkeys } = makeRing(3);
      // Use keys[1] private key but claim to be at index 0
      expect(() => ringSign('test', pubkeys, 0, keys[1].privateKey))
        .toThrow(ValidationError);
    });

    it('rejects non-string message', () => {
      const { keys, pubkeys } = makeRing(3);
      expect(() => ringSign(123 as any, pubkeys, 0, keys[0].privateKey))
        .toThrow(ValidationError);
    });

    it('rejects non-array ring', () => {
      const { keys } = makeRing(3);
      expect(() => ringSign('test', 'not-an-array' as any, 0, keys[0].privateKey))
        .toThrow(ValidationError);
    });

    it('rejects non-string privateKey', () => {
      const { pubkeys } = makeRing(3);
      expect(() => ringSign('test', pubkeys, 0, 123 as any))
        .toThrow(ValidationError);
    });

    it('detects mixed-case hex duplicate ring members', () => {
      const { keys, pubkeys } = makeRing(3);
      const upper = pubkeys[0].toUpperCase();
      const dupeRing = [pubkeys[0], upper, pubkeys[2]];
      expect(() => ringSign('test', dupeRing, 0, keys[0].privateKey))
        .toThrow('duplicate');
    });

    it('handles uppercase hex pubkeys correctly', () => {
      const { keys, pubkeys } = makeRing(3);
      const upperRing = pubkeys.map(pk => pk.toUpperCase());
      const sig = ringSign('upper test', upperRing, 0, keys[0].privateKey);
      // Ring is normalised to lowercase in the returned signature
      expect(sig.ring).toEqual(pubkeys.map(pk => pk.toLowerCase()));
      expect(ringVerify(sig)).toBe(true);
    });

    it('verifies a signature whose stored ring has uppercase keys', () => {
      const { keys, pubkeys } = makeRing(3);
      const sig = ringSign('test', pubkeys, 0, keys[0].privateKey);
      // Simulate deserialisation with uppercase ring
      const upperSig = { ...sig, ring: sig.ring.map(pk => pk.toUpperCase()) };
      expect(ringVerify(upperSig)).toBe(true);
    });
  });
});
