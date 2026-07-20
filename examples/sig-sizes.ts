import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ringSign, lsagSign } from '../dist/index.js';

const sizes = [2, 5, 10, 50, 100];

for (const n of sizes) {
  // Generate matching key pairs
  const keys = Array.from({ length: n }, () => {
    const priv = secp256k1.utils.randomSecretKey();
    const pub = bytesToHex(secp256k1.getPublicKey(priv, true)).slice(2);
    return { priv: bytesToHex(priv), pub };
  });
  
  const ring = keys.map(k => k.pub);
  const signerPriv = keys[0].priv;
  
  const sagSig = ringSign('test', ring, 0, signerPriv);
  const sagJson = JSON.stringify(sagSig);
  
  const lsagSig = lsagSign('test', ring, 0, signerPriv, 'election-1');
  const lsagJson = JSON.stringify(lsagSig);
  
  console.log(`Ring size ${n}:`);
  console.log(`  SAG JSON: ${sagJson.length} bytes`);
  console.log(`  LSAG JSON: ${lsagJson.length} bytes`);
  console.log(`  SAG raw: ${32 + n * 32} bytes (c0 32 + ${n} x s_i 32)`);
  console.log(`  LSAG raw: ${33 + 32 + n * 32} bytes (keyImage 33 + c0 32 + ${n} x s_i 32)`);
  console.log();
}
