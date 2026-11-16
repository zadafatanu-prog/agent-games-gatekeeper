// Smoke test: prove the valid scenario end to end and check the public
// signals. Also verifies the commitment hypothesis: public[0] is
// Poseidon(salt, taskId). Run: node test/proof-smoke.js
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');
const { poseidon2 } = require('poseidon-lite');

const DIR = path.join(__dirname, '..');
const WASM = path.join(DIR, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(DIR, 'circuits', 'gatekeeper_final.zkey');
const VK = JSON.parse(fs.readFileSync(path.join(DIR, 'circuits', 'verification_key.json'), 'utf8'));

const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const toField = (x) => { const r = BigInt(x) % FIELD_PRIME; return r < 0n ? r + FIELD_PRIME : r; };

// Deterministic test values (not from any real task).
const VK_HASH = '0x' + keccak_256(Buffer.from('registered-vk-test', 'utf8'));
const RECIPIENT = '0x' + 'de42'.padEnd(40, '0');
const TASK_ID = 'gk_24_9d1';
const taskIdField = toField(BigInt('0x' + keccak_256(Buffer.from(TASK_ID, 'utf8'))));

async function main() {
  const salt = '0x' + crypto.randomBytes(32).toString('hex');
  const input = {
    registeredVkHash: VK_HASH,
    proofVkHash: VK_HASH,
    minimum: '1000',
    publicBalance: '1460',
    expiryBlock: '19842201',
    currentBlock: '19832000',
    recipient: RECIPIENT,
    conditionRecipient: RECIPIENT,
    amount: '500',
    maxTransfer: '1000',
    decision: '1',
    taskId: taskIdField.toString(),
    salt,
  };
  console.log('input taskId (keccak256 mod p):', input.taskId);
  console.log('input salt:', salt);

  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const proveMs = Date.now() - t0;
  console.log(`fullProve: ${proveMs} ms`);

  const t1 = Date.now();
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  console.log(`verify: ${ok} (${Date.now() - t1} ms)`);
  if (!ok) { console.error('PROOF DID NOT VERIFY'); process.exit(1); }

  const names = ['commitment', 'registeredVkHash', 'proofVkHash', 'minimum',
    'publicBalance', 'expiryBlock', 'currentBlock', 'recipient',
    'conditionRecipient', 'amount', 'maxTransfer', 'decision', 'taskId'];
  console.log(`\npublic signals (${publicSignals.length}):`);
  publicSignals.forEach((s, i) => console.log(`  [${i}] ${names[i]} = ${s}`));

  // Check the documented order: the 12 task fields must match the inputs.
  const expect = {
    1: toField(VK_HASH).toString(),
    2: toField(VK_HASH).toString(),
    3: '1000', 4: '1460', 5: '19842201', 6: '19832000',
    7: toField(RECIPIENT).toString(), 8: toField(RECIPIENT).toString(),
    9: '500', 10: '1000', 11: '1', 12: taskIdField.toString(),
  };
  let orderOk = true;
  for (const [i, v] of Object.entries(expect)) {
    if (publicSignals[i] !== v) { console.error(`  MISMATCH [${i}] ${names[i]}: got ${publicSignals[i]}, want ${v}`); orderOk = false; }
  }
  console.log(orderOk ? '\npublic-signal order: OK (matches documented order)' : '\npublic-signal order: MISMATCH');

  // Commitment hypothesis: public[0] == Poseidon(salt, taskId).
  const commitment = poseidon2([toField(salt), taskIdField]);
  const commitOk = BigInt(commitment).toString() === publicSignals[0];
  console.log(`Poseidon(salt, taskId) = ${BigInt(commitment).toString()}`);
  console.log(`public[0]            = ${publicSignals[0]}`);
  console.log(commitOk ? 'commitment hypothesis: CONFIRMED (public[0] = Poseidon(salt, taskId))' : 'commitment hypothesis: NOT CONFIRMED');

  if (!orderOk || !commitOk) process.exit(1);
  console.log('\nSMOKE TEST PASSED');
  // snarkjs leaves a handle open after fullProve; exit explicitly.
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
