// Probe the official gatekeeper.wasm for its input signal names.
//
// Circom 2 WASM resolves input signals by FNV-1a 64-bit hash of the signal
// name. The WASM exports getInputSignalSize(hMSB, hLSB) which returns the
// signal's size, or a negative value when the name does not exist.
// This script asks the compiled circuit itself which candidate names are
// real — it does not trust any article's list. Run: node test/probe-wasm.js
'use strict';
const fs = require('fs');
const path = require('path');

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');

// FNV-1a 64-bit, exactly as snarkjs computes it (see
// node_modules/snarkjs/build/browser.esm.js, function fnvHash).
function fnvHash(str) {
  const uint64Max = BigInt(2) ** BigInt(64);
  let hash = BigInt('0xCBF29CE484222325');
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001b3);
    hash %= uint64Max;
  }
  let shash = hash.toString(16);
  shash = '0'.repeat(16 - shash.length) + shash;
  return shash;
}

function splitHash(h) {
  return {
    hMSB: parseInt(h.slice(0, 8), 16),
    hLSB: parseInt(h.slice(8, 16), 16),
  };
}

const CANDIDATES = [
  // The 13 names reported by other participants (to be verified, not trusted).
  'taskId', 'minimum', 'publicBalance', 'expiryBlock', 'currentBlock',
  'recipient', 'conditionRecipient', 'amount', 'maxTransfer',
  'registeredVkHash', 'proofVkHash', 'salt', 'decision',
  // Decoys: plausible names that must NOT exist (proves the probe discriminates).
  'task_id', 'taskID', 'TaskId', 'TASKID', 'minimum_balance', 'balance',
  'public_balance', 'publicBalance2', 'expiry', 'expiry_block', 'current',
  'current_block', 'blockHeight', 'deadline', 'amount_paid', 'value', 'max',
  'max_transfer', 'vk', 'hash', 'commitment', 'proofTx', 'proof_tx',
  'sender', 'receiver', 'token', 'nonce', 'decision_flag', 'approve',
  'reject', 'registered_vk', 'proof_vk', 'condition_recipient',
  'registeredVk', 'proofVk', 'vkHash', 'salt2', 'taskHash', 'MINIMUM',
  'Decision', 'Salt', 'Amount', 'Recipient', 'input', 'output',
];

async function main() {
  const code = fs.readFileSync(WASM_PATH);
  const memory = new WebAssembly.Memory({ initial: 2000 });
  const instance = await WebAssembly.instantiate(await WebAssembly.compile(code), {
    env: { memory },
    runtime: {
      printDebug: () => {},
      exceptionHandler: (c) => { throw new Error('wasm exception ' + c); },
      printErrorMessage: () => {},
      writeBufferMessage: () => {},
      showSharedRWMemory: () => {},
      error: () => { throw new Error('wasm error'); },
      log: () => {},
      logGetSignal: () => {},
      logSetSignal: () => {},
      logStartComponent: () => {},
      logFinishComponent: () => {},
    },
  });
  const ex = instance.exports;

  const version = typeof ex.getVersion === 'function'
    ? `${ex.getVersion()}.${ex.getMinorVersion()}.${ex.getPatchVersion()}`
    : 'unknown (circom 1?)';
  const inputSize = ex.getInputSize();
  const witnessSize = ex.getWitnessSize();
  console.log(`circom version: ${version}`);
  console.log(`getInputSize() = ${inputSize}`);
  console.log(`getWitnessSize() = ${witnessSize}`);
  console.log(`getFieldNumLen32() = ${ex.getFieldNumLen32()}`);
  console.log(`nPublic (from vk) = 13 (see circuits/verification_key.json)`);
  console.log('');

  const found = [];
  const missing = [];
  for (const name of CANDIDATES) {
    const h = fnvHash(name);
    const { hMSB, hLSB } = splitHash(h);
    let size;
    try {
      size = ex.getInputSignalSize(hMSB, hLSB);
    } catch (e) {
      size = -1;
    }
    // In this WASM build a missing signal returns size 0 (not a negative
    // value); a real scalar input returns size 1. snarkjs treats < 0 as
    // "not found" and would reject a size-0 name as "too many values".
    if (typeof size === 'number' && size >= 1) found.push({ name, size });
    else missing.push(name);
  }

  console.log(`FOUND (${found.length}):`);
  for (const f of found) console.log(`  ${f.name} (size ${f.size})`);
  console.log('');
  console.log(`NOT FOUND (${missing.length} decoys correctly rejected): ${missing.join(', ')}`);
  console.log('');
  if (found.length === inputSize) {
    console.log(`MATCH: found ${found.length} names == getInputSize() ${inputSize}. No hidden inputs.`);
  } else {
    console.log(`MISMATCH: found ${found.length} names but getInputSize() = ${inputSize}. Some inputs are unnamed by this candidate list.`);
    process.exitCode = 1;
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
