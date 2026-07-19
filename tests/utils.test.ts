import { describe, it, expect } from 'vitest';
import { N, scalarToHex, hexToScalar } from '../src/utils.js';
import { ValidationError } from '../src/errors.js';

describe('scalar hex canonicalisation', () => {
  describe('scalarToHex (sign path) emits canonical 64-char lowercase', () => {
    // Representative values: smallest, a value with high nibbles set, and the
    // largest valid scalar. Proves the encoder never emits short or uppercase
    // hex, so tightening hexToScalar cannot reject a legitimately-signed value.
    const values = [1n, 255n, 0x0abcdefn, (N - 1n) / 2n, N - 1n];

    it('always matches /^[0-9a-f]{64}$/', () => {
      for (const v of values) {
        expect(scalarToHex(v)).toMatch(/^[0-9a-f]{64}$/);
      }
    });

    it('round-trips through hexToScalar', () => {
      for (const v of values) {
        expect(hexToScalar(scalarToHex(v))).toBe(v);
      }
    });
  });

  describe('hexToScalar requires canonical form', () => {
    it('accepts an exactly-64 lowercase hex scalar', () => {
      const canonical = '0'.repeat(63) + '1';
      expect(hexToScalar(canonical)).toBe(1n);
    });

    it('rejects an upper-cased twin that decodes to the same value', () => {
      const lower = 'abcdef' + '0'.repeat(58);
      const upper = lower.toUpperCase();
      // Both strings denote the same integer...
      expect(BigInt('0x' + upper)).toBe(hexToScalar(lower));
      // ...but only the canonical (lowercase) form is accepted.
      expect(() => hexToScalar(upper)).toThrow(ValidationError);
    });

    it('rejects a stripped leading-zero-nibble twin', () => {
      // '1' and the 64-char padded form both decode to 1n; only the padded
      // (canonical) form is accepted, killing length malleability.
      expect(hexToScalar('0'.repeat(63) + '1')).toBe(1n);
      expect(() => hexToScalar('1')).toThrow(ValidationError);
    });

    it('rejects a scalar >= curve order N', () => {
      expect(() => hexToScalar(N.toString(16).padStart(64, '0'))).toThrow('curve order');
    });
  });
});
