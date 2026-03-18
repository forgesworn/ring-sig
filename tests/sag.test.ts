import { describe, it, expect } from 'vitest';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import {
  MAX_RING_SIZE,
  ringSign,
  ringVerify,
} from '../src/sag.js';

function generateKeyPair(): { privateKey: string; publicKey: string } {
  const priv = secp256k1.utils.randomPrivateKey();
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
      // Flip a byte in one response
      const r = sig.responses[1];
      sig.responses[1] = 'ff' + r.slice(2);
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
});
