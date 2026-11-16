// Attempt to reproduce the platform's registered gatekeeper vkHash
// (0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0,
// from /api/circuit-info) from the verification key exported from the
// official zkey. Another participant tried 12 serialization variants
// without a match; this script re-tries the most plausible ones and
// records the outcome honestly. Run: node test/vkhash-check.js
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { keccak_256 } = require('js-sha3');

const VK = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'verification_key.json'), 'utf8'));
const TARGET = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function keccakHex(buf) { return '0x' + keccak_256(buf); }
function sha256Hex(buf) { return '0x' + crypto.createHash('sha256').update(buf).digest('hex'); }
function to32(x) { return Buffer.from(BigInt(x).toString(16).padStart(64, '0'), 'hex'); }

// A Groth16 vk point is [x, y] in G1, or [[x0, x1], [y0, y1]] in G2.
function g1Bytes(p) { return Buffer.concat([to32(p[0]), to32(p[1])]); }
function g2Bytes(p) {
  // G2 points are stored as [[x0, x1], [y0, y1]]; two orderings exist.
  return Buffer.concat([to32(p[0][0]), to32(p[0][1]), to32(p[1][0]), to32(p[1][1])]);
}

const variants = {};
variants['keccak256(compact JSON)'] = keccakHex(Buffer.from(JSON.stringify(VK), 'utf8'));
variants['sha256(compact JSON)'] = sha256Hex(Buffer.from(JSON.stringify(VK), 'utf8'));
variants['keccak256(indented JSON, 2 spaces)'] = keccakHex(Buffer.from(JSON.stringify(VK, null, 2), 'utf8'));
variants['keccak256(sorted-keys JSON)'] = keccakHex(Buffer.from(JSON.stringify(VK, Object.keys(VK).sort()), 'utf8'));

// Flattened curve points: alpha1, beta2, gamma2, delta2, IC points.
const flat = Buffer.concat([
  g1Bytes(VK.vk_alpha_1),
  g2Bytes(VK.vk_beta_2),
  g2Bytes(VK.vk_gamma_2),
  g2Bytes(VK.vk_delta_2),
  ...VK.IC.map(g1Bytes),
]);
variants['keccak256(alpha1||beta2||gamma2||delta2||IC)'] = keccakHex(flat);
variants['sha256(alpha1||beta2||gamma2||delta2||IC)'] = sha256Hex(flat);
variants['keccak256(IC points only)'] = keccakHex(Buffer.concat(VK.IC.map(g1Bytes)));

// G2 with the alternate limb order (x1, x0), which some serializers use.
function g2BytesSwapped(p) {
  return Buffer.concat([to32(p[0][1]), to32(p[0][0]), to32(p[1][1]), to32(p[1][0])]);
}
const flatSwapped = Buffer.concat([
  g1Bytes(VK.vk_alpha_1),
  g2BytesSwapped(VK.vk_beta_2),
  g2BytesSwapped(VK.vk_gamma_2),
  g2BytesSwapped(VK.vk_delta_2),
  ...VK.IC.map(g1Bytes),
]);
variants['keccak256(points, G2 limbs swapped)'] = keccakHex(flatSwapped);

let matched = false;
for (const [name, hash] of Object.entries(variants)) {
  const ok = hash.toLowerCase() === TARGET.toLowerCase();
  if (ok) matched = true;
  console.log(`[${ok ? 'MATCH' : 'no match'}] ${name}: ${hash}`);
}
console.log(`\ntarget: ${TARGET}`);
console.log(matched
  ? 'REPRODUCED: one variant matches the registered hash.'
  : 'NOT REPRODUCED: none of the tried serializations match. The platform (zkVerify/Kurier) computes the registered hash over its own canonical serialization, which this build does not reproduce. This does not affect local proof generation — proofs verify against the exported vk — but it is an open item for going live (see README).');
process.exit(matched ? 0 : 2);
