/**
 * LSAG Voting — Key Image Double-Spend Detection
 *
 * Demonstrates how LSAG enables anonymous voting with double-vote prevention.
 * The key image `I = x * H_p(P || electionId)` is deterministic per
 * (private key, election). Signing twice in the same election produces the
 * same key image, exposing the duplicate without revealing the voter's identity.
 *
 * Run with: npx tsx examples/voting-lsag.ts
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import {
  lsagSign,
  lsagVerify,
  computeKeyImage,
  hasDuplicateKeyImage,
  type LsagSignature,
} from '@forgesworn/ring-sig';

// --- Setup -------------------------------------------------------------------

// Generate six key pairs — these are eligible voters in the election
const voters = Array.from({ length: 6 }, (_, i) => {
  const priv = bytesToHex(secp256k1.utils.randomPrivateKey());
  // x-only public key: remove the 02/03 prefix from the compressed key (BIP-340)
  const pub = bytesToHex(secp256k1.getPublicKey(priv, true)).slice(2);
  return { index: i, priv, pub };
});

// All eligible public keys form the ring (the anonymity set)
const ring = voters.map(v => v.pub);
const electionId = 'open-source-grant-vote-2026';

console.log(`Election: ${electionId}`);
console.log(`Eligible voters: ${ring.length}`);
console.log();

// --- Pre-compute key images --------------------------------------------------
//
// The ballot authority can pre-compute key images for all eligible voters
// before voting opens. This lets them check eligibility without requiring
// a signature, and initialise the duplicate register.

console.log('Pre-computing key images for all eligible voters...');
const eligibleKeyImages = voters.map(v =>
  computeKeyImage(v.priv, v.pub, electionId)
);
console.log(`  ${eligibleKeyImages.length} key images registered`);
console.log();

// The live register tracks which key images have cast a ballot
const castKeyImages: string[] = [];

// --- Ballot processing -------------------------------------------------------

function castBallot(voterIndex: number, candidate: string): 'accepted' | 'rejected' {
  const voter = voters[voterIndex];

  const sig: LsagSignature = lsagSign(
    candidate,
    ring,
    voterIndex,
    voter.priv,
    electionId,
  );

  // 1. Cryptographic validity
  if (!lsagVerify(sig)) {
    console.log(`  Voter [${voterIndex}] → REJECTED (invalid signature)`);
    return 'rejected';
  }

  // 2. Eligibility check — key image must be in the pre-registered set
  if (!hasDuplicateKeyImage(sig.keyImage, eligibleKeyImages)) {
    console.log(`  Voter [${voterIndex}] → REJECTED (not in eligible set)`);
    return 'rejected';
  }

  // 3. Double-vote check — key image must not have been used yet
  if (hasDuplicateKeyImage(sig.keyImage, castKeyImages)) {
    console.log(`  Voter [${voterIndex}] → REJECTED (duplicate key image — double vote)`);
    return 'rejected';
  }

  castKeyImages.push(sig.keyImage);
  console.log(`  Voter [${voterIndex}] → ACCEPTED for '${candidate}'`);
  return 'accepted';
}

console.log('--- Voting round ---');
castBallot(0, 'Proposal Alpha');
castBallot(1, 'Proposal Beta');
castBallot(2, 'Proposal Alpha');
castBallot(3, 'Proposal Alpha');

console.log();
console.log('--- Voter 1 attempts a second vote ---');
castBallot(1, 'Proposal Alpha'); // duplicate key image — rejected

console.log();
console.log('--- Remaining voters cast ballots ---');
castBallot(4, 'Proposal Beta');
castBallot(5, 'Proposal Beta');

console.log();
console.log(`Ballots accepted: ${castKeyImages.length} of ${voters.length} eligible voters`);
console.log();

// --- Cross-election unlinkability --------------------------------------------
//
// Key images are scoped to an electionId. The same voter's image in a
// different election is entirely unrelated — signatures cannot be linked
// across contexts.

const nextElection = 'open-source-grant-vote-2027';
const imageThisYear = computeKeyImage(voters[0].priv, voters[0].pub, electionId);
const imageNextYear = computeKeyImage(voters[0].priv, voters[0].pub, nextElection);

console.log('--- Cross-election unlinkability ---');
console.log(`Voter [0] key image (${electionId.slice(-4)}): ${imageThisYear}`);
console.log(`Voter [0] key image (${nextElection.slice(-4)}):  ${imageNextYear}`);
console.log(`Images are identical: ${imageThisYear === imageNextYear}`); // false
console.log();
console.log('The voter is anonymous across elections — images share no common bits.');
