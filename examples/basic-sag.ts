/**
 * SAG Ring Signature — Basic Example
 *
 * Demonstrates anonymous group membership proofs using SAG (Spontaneous
 * Anonymous Group) signatures. The signer proves they are one of N public
 * key holders without revealing which one.
 *
 * Run with: npx tsx examples/basic-sag.ts
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { ringSign, ringVerify, type RingSignature } from '@forgesworn/ring-sig';

// --- Key generation -------------------------------------------------------

// Generate five key pairs representing an anonymous group of signers
const participants = Array.from({ length: 5 }, (_, i) => {
  const priv = bytesToHex(secp256k1.utils.randomPrivateKey());
  // x-only public key: compressed form minus the 02/03 prefix (BIP-340 convention)
  const pub = bytesToHex(secp256k1.getPublicKey(priv, true)).slice(2);
  return { index: i, priv, pub };
});

const ring = participants.map(p => p.pub);

console.log(`Ring size: ${ring.length} members`);
console.log(`Ring members (x-only public keys):`);
ring.forEach((pk, i) => console.log(`  [${i}] ${pk}`));
console.log();

// --- Sign -----------------------------------------------------------------

// Member at index 2 signs a statement — their position stays hidden
const SIGNER_INDEX = 2;
const message = 'I attest that the audit was conducted fairly.';

console.log(`Signing as member [${SIGNER_INDEX}] (identity hidden from verifier)...`);
const sig: RingSignature = ringSign(
  message,
  ring,
  SIGNER_INDEX,
  participants[SIGNER_INDEX].priv,
);

console.log(`Signature produced.`);
console.log(`  c0:        ${sig.c0}`);
console.log(`  responses: ${sig.responses.length} scalars (one per ring member)`);
console.log(`  domain:    ${sig.domain ?? 'sag-v1 (default)'}`);
console.log();

// --- Verify ---------------------------------------------------------------

console.log(`Verifying signature...`);
const valid = ringVerify(sig);
console.log(`  Valid: ${valid}`); // true

// Demonstrate tamper detection
const tamperedMessage: RingSignature = { ...sig, message: 'Different message' };
const tamperedRing: RingSignature = {
  ...sig,
  ring: [...sig.ring.slice(0, -1), participants[4].pub.replace('a', 'b')],
};

console.log(`  Tampered message valid: ${ringVerify(tamperedMessage)}`); // false
console.log(`  Tampered ring valid:    ${ringVerify(tamperedRing)}`);    // false
console.log();

// --- Serialisation --------------------------------------------------------

// Signatures are plain JSON — safe to transmit over any channel
const json = JSON.stringify(sig, null, 2);
const restored: RingSignature = JSON.parse(json);
console.log(`Serialise → JSON → deserialise → re-verify: ${ringVerify(restored)}`);
console.log();

// --- Custom domain separator ----------------------------------------------

// Use a custom domain to prevent cross-application signature replay
const domainSig = ringSign(
  message,
  ring,
  SIGNER_INDEX,
  participants[SIGNER_INDEX].priv,
  'my-app-attestation-v1',
);

console.log(`Custom domain: '${domainSig.domain}'`);
console.log(`Custom domain signature valid: ${ringVerify(domainSig)}`);

// A signature from one domain does NOT verify under another
const crossDomain: RingSignature = { ...domainSig, domain: 'wrong-domain' };
console.log(`Cross-domain replay valid:     ${ringVerify(crossDomain)}`); // false
