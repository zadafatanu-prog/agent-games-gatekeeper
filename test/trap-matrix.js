// Circuit-level trap matrix: for every circuit-checkable trap variety,
// try to prove BOTH decisions and confirm the circuit only certifies the
// correct one. A dishonest APPROVE must fail at witness generation (the
// GatekeeperEvaluation assert); the correct decision must prove and verify.
//
// NOTE: PROOF_REUSED is not in this matrix — the circuit has no reuse
// input, so a reused proof's inputs are otherwise valid and decision=1
// WOULD prove. Reuse is an off-circuit check (the local seen-set) and is
// tested at the HTTP level in test/http-test.js.
//
// Run: node test/trap-matrix.js
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');

const DIR = path.join(__dirname, '..');
const WASM = path.join(DIR, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(DIR, 'circuits', 'gatekeeper_final.zkey');
const VK = JSON.parse(fs.readFileSync(path.join(DIR, 'circuits', 'verification_key.json'), 'utf8'));

const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const toField = (x) => { const r = BigInt(x) % FIELD_PRIME; return r < 0n ? r + FIELD_PRIME : r; };

const VK_A = '0x' + keccak_256(Buffer.from('vk-a', 'utf8'));
const VK_B = '0x' + keccak_256(Buffer.from('vk-b', 'utf8'));
const ADDR_A = '0x' + 'de42'.padEnd(40, '0');
const ADDR_B = '0x' + 'beef'.padEnd(40, '0');
const TASK_ID = toField(BigInt('0x' + keccak_256(Buffer.from('gk_matrix_1', 'utf8')))).toString();

function baseInput(overrides = {}) {
  return {
    registeredVkHash: VK_A,
    proofVkHash: VK_A,
    minimum: '1000',
    publicBalance: '1460',
    expiryBlock: '19842201',
    currentBlock: '19832000',
    recipient: ADDR_A,
    conditionRecipient: ADDR_A,
    amount: '500',
    maxTransfer: '1000',
    taskId: TASK_ID,
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
    ...overrides,
  };
}

// Each case: name, input overrides, the CORRECT decision (1 = approve).
const CASES = [
  { name: 'valid condition', input: {}, correct: 1 },
  { name: 'VK_SUBSTITUTION (proof VK != registered VK)', input: { proofVkHash: VK_B }, correct: 0 },
  { name: 'THRESHOLD_MISMATCH (balance 900 < minimum 1000)', input: { publicBalance: '900' }, correct: 0 },
  { name: 'EXPIRED_CONDITION (current 19843000 > expiry 19842201)', input: { currentBlock: '19843000' }, correct: 0 },
  { name: 'RECIPIENT_MISMATCH', input: { recipient: ADDR_B }, correct: 0 },
  { name: 'AMOUNT_OVERFLOW (amount 1500 > cap 1000)', input: { amount: '1500' }, correct: 0 },
  // Boundaries.
  { name: 'boundary: balance == minimum (1000 == 1000) is VALID', input: { publicBalance: '1000' }, correct: 1 },
  { name: 'boundary: amount == max (1000 == 1000) is VALID', input: { amount: '1000' }, correct: 1 },
  { name: 'boundary: current == expiry (19842201 == 19842201) is EXPIRED', input: { currentBlock: '19842201' }, correct: 0 },
];

async function tryProve(input, decision) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      { ...input, decision: String(decision) }, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    return { proved: true, verified: ok, ms: Date.now() - t0 };
  } catch (e) {
    return { proved: false, error: String(e.message || e).split('\n')[0], ms: Date.now() - t0 };
  }
}

async function main() {
  let pass = 0;
  let fail = 0;
  const timings = [];
  for (const c of CASES) {
    const input = baseInput(c.input);
    for (const decision of [1, 0]) {
      const shouldProve = decision === c.correct;
      const r = await tryProve(input, decision);
      const ok = shouldProve ? (r.proved && r.verified) : !r.proved;
      if (r.proved) timings.push(r.ms);
      if (ok) pass++; else fail++;
      const verdict = shouldProve
        ? (r.proved ? `proved + verified (${r.ms} ms)` : `FAILED TO PROVE: ${r.error}`)
        : (r.proved ? `PROVED (BAD — dishonest decision is provable!)` : `refused (${r.error.slice(0, 90)})`);
      console.log(`[${ok ? 'PASS' : 'FAIL'}] ${c.name} | decision=${decision} | ${verdict}`);
    }
  }
  console.log(`\n${pass} passed, ${fail} failed (${CASES.length * 2} checks)`);
  if (timings.length) {
    console.log(`prove timings (successful): min ${Math.min(...timings)} ms, max ${Math.max(...timings)} ms, mean ${Math.round(timings.reduce((a, b) => a + b, 0) / timings.length)} ms — deadline is 60000 ms`);
  }
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
