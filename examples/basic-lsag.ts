/**
 * LSAG Ring Signature — Basic Example
 *
 * Demonstrates linkable anonymous signatures using LSAG (Linkable Spontaneous
 * Anonymous Group). Signers remain anonymous within the ring, but if the same
 * key signs twice in the same context (same electionId), the duplicate key
 * image reveals the double-action — without revealing who signed.
 *
 * Common use cases: anonymous voting, rate-limiting, double-spend prevention.
 *
 * Run with: npx tsx examples/basic-lsag.ts
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

// --- Key generation -------------------------------------------------------

// Generate eight key pairs representing eligible voters
const voters = Array.from({ length: 8 }, (_, i) => {
  const priv = bytesToHex(secp256k1.utils.randomPrivateKey());
  const pub = bytesToHex(secp256k1.getPublicKey(priv, true)).slice(2);
  return { index: i, priv, pub };
});

const ring = voters.map(v => v.pub);
const electionId = 'community-grant-vote-2026';

console.log(`Election: ${electionId}`);
console.log(`Ring size: ${ring.length} eligible voters`);
console.log();

// Accumulated key images — the ballot box's double-vote register
const acceptedKeyImages: string[] = [];
let voteCount = 0;

// --- Helper: cast a vote --------------------------------------------------

function castVote(voterIndex: number, candidate: string): void {
  console.log(`Voter [${voterIndex}] casting vote for '${candidate}'...`);

  const sig: LsagSignature = lsagSign(
    candidate,
    ring,
    voterIndex,
    voters[voterIndex].priv,
    electionId,
  );

  // Step 1: Verify the signature is cryptographically valid
  if (!lsagVerify(sig)) {
    console.log(`  REJECTED: invalid signature`);
    return;
  }

  // Step 2: Check for double-voting using constant-time key image comparison
  if (hasDuplicateKeyImage(sig.keyImage, acceptedKeyImages)) {
    console.log(`  REJECTED: duplicate key image — double vote detected`);
    console.log(`  Key image: ${sig.keyImage}`);
    return;
  }

  // Accept the vote and record the key image
  acceptedKeyImages.push(sig.keyImage);
  voteCount++;
  console.log(`  ACCEPTED (vote #${voteCount})`);
  console.log(`  Key image: ${sig.keyImage}`);
}

// --- Voting ---------------------------------------------------------------

castVote(0, 'proposal-A');
castVote(1, 'proposal-B');
castVote(2, 'proposal-A');
castVote(3, 'proposal-A');

console.log();

// Voter 1 attempts to vote again — detected via duplicate key image
console.log(`Voter [1] attempting a second vote...`);
castVote(1, 'proposal-A');

console.log();

// Voter 5 has not voted yet — accepted
castVote(5, 'proposal-B');

console.log();
console.log(`Final vote count: ${voteCount} accepted votes`);
console.log(`Recorded key images: ${acceptedKeyImages.length}`);
console.log();

// --- Pre-compute key images -----------------------------------------------

// You can compute a key image before signing — useful to check eligibility
// without requiring the voter to produce a full signature first.

console.log(`--- Pre-computing key images ---`);
const preImage = computeKeyImage(voters[2].priv, voters[2].pub, electionId);
console.log(`Pre-computed key image for voter [2]: ${preImage}`);
console.log(
  `Has voter [2] already voted? ${hasDuplicateKeyImage(preImage, acceptedKeyImages)}`,
); // true — voter 2 voted above

const unvotedImage = computeKeyImage(voters[7].priv, voters[7].pub, electionId);
console.log();
console.log(`Pre-computed key image for voter [7]: ${unvotedImage}`);
console.log(
  `Has voter [7] already voted? ${hasDuplicateKeyImage(unvotedImage, acceptedKeyImages)}`,
); // false — voter 7 has not voted
console.log();

// --- Cross-context unlinkability ------------------------------------------

// The same voter's key image changes completely when the electionId changes.
// Signatures from different elections cannot be linked to the same person.

const differentElection = 'community-grant-vote-2027';
const imageThisYear = computeKeyImage(voters[0].priv, voters[0].pub, electionId);
const imageNextYear = computeKeyImage(voters[0].priv, voters[0].pub, differentElection);

console.log(`--- Cross-context unlinkability ---`);
console.log(`Voter [0] key image this election: ${imageThisYear}`);
console.log(`Voter [0] key image next election: ${imageNextYear}`);
console.log(`Images are identical: ${imageThisYear === imageNextYear}`); // false
