// Proof Gatekeeper agent for zkVerify Agent Games Season 01.
//
// Single-file Node.js server (no framework, plain `http`). It receives a
// signed task envelope, decides APPROVE or REJECT by walking the documented
// 7-trap checklist, generates a Groth16 proof of the decision with the
// tournament's official gatekeeper circuit, verifies that proof locally,
// and returns a signed response — all inside the 60-second deadline.
//
// LOCAL BUILD. The HMAC secret below is a TEST secret for local testing
// only. The real platform secret is issued at registration (Rotate Secret)
// and must be supplied via AGENT_GAMES_HMAC_SECRET. Never commit a real
// secret to a repository.
//
// Run:  AGENT_GAMES_HMAC_SECRET=<test-secret> node server.js
//   or: node server.js            (uses the built-in TEST secret; health
//                                 endpoint reports hmacConfigured:false)
// Env:  PORT (default 8787)
//       AGENT_GAMES_HMAC_SECRET (default: the TEST secret below)
//       GATEKEEPER_TASK_ID_MODE (keccak | numeric | hex; default keccak)
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');

// ---------------------------------------------------------------- config

const PORT = Number(process.env.PORT || 8787);

// TEST-ONLY secret. This value is a placeholder for local development and
// testing. The real platform secret comes from registration and is set via
// the AGENT_GAMES_HMAC_SECRET environment variable.
const TEST_HMAC_SECRET = 'test-only-local-secret-do-not-use-in-production';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || TEST_HMAC_SECRET;
const HMAC_CONFIGURED = Boolean(process.env.AGENT_GAMES_HMAC_SECRET);
const TASK_ID_MODE = (process.env.GATEKEEPER_TASK_ID_MODE || 'keccak').toLowerCase();

const DIR = __dirname;
const WASM_PATH = path.join(DIR, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(DIR, 'circuits', 'gatekeeper_final.zkey');
const VK = JSON.parse(fs.readFileSync(path.join(DIR, 'circuits', 'verification_key.json'), 'utf8'));

const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MiB cap on incoming bodies
const PROVE_TIMEOUT_MS = 30_000; // fail closed if proving ever hangs

// ---------------------------------------------------------------- field math

const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else if (typeof x === 'string' && x.startsWith('0x')) b = BigInt(x);
  else b = BigInt(x);
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

// The envelope's task_id is a string (e.g. "gk_24_9d1"); the circuit needs
// a field element. Default mapping: keccak256(task_id as UTF-8) mod p.
// This mapping is UNCONFIRMED against the platform — it is the one value
// the platform recomputes from the envelope, so a practice task is the
// verification step. Alternatives (GATEKEEPER_TASK_ID_MODE): "numeric"
// (digits of the id) and "hex" (hex chars of the id).
function taskIdToField(taskId) {
  const id = String(taskId || '');
  if (TASK_ID_MODE === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? toField(BigInt(digits)) : 0n;
  }
  if (TASK_ID_MODE === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? toField(BigInt('0x' + hex)) : 0n;
  }
  return toField(BigInt('0x' + keccak_256(Buffer.from(id, 'utf8'))));
}

// ---------------------------------------------------------------- HMAC

function hmacHex(secret, bodyBuffer) {
  return crypto.createHmac('sha256', secret).update(bodyBuffer).digest('hex');
}

function verifySignature(rawBody, headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return false;
  // Accept a bare hex digest, or one prefixed with "sha256=".
  const given = headerValue.startsWith('sha256=') ? headerValue.slice(7) : headerValue;
  const expected = hmacHex(HMAC_SECRET, rawBody);
  const givenBuf = Buffer.from(given, 'utf8');
  const expectedBuf = Buffer.from(expected, 'utf8');
  if (givenBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(givenBuf, expectedBuf);
}

// ---------------------------------------------------------------- decision

// proof_tx (lowercased) -> task_id that first used it. A retry of the SAME
// task_id is not a reuse; the same proof_tx under another task_id is.
const seenProofTx = new Map();

// Idempotency cache: task_id -> exact response body string. The platform
// may retry after a network failure; a repeat returns the byte-identical
// cached body without re-deciding (and without tripping reuse detection).
const responseCache = new Map();

// ---------------------------------------------------------------- seen-set persistence

// The seen-proof set survives server restarts via an append-only JSONL file
// (one {"proof_tx","task_id"} line per first sighting). Loaded at startup;
// each new sighting is appended synchronously. On hosts with an ephemeral
// filesystem (e.g. Railway without a mounted volume) the file survives a
// process restart inside a deployment, not a redeploy — a redeploy resets
// the set, so the first task after a redeploy cannot be flagged as a reuse
// of a pre-redeploy proof. The response cache stays in-memory by design:
// a retry re-decides deterministically (same verdict, fresh salt/proof).
const SEEN_FILE = process.env.GATEKEEPER_SEEN_FILE || path.join(DIR, 'seen-proofs.jsonl');

function loadSeenProofTx() {
  let n = 0;
  try {
    for (const line of fs.readFileSync(SEEN_FILE, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line);
        if (typeof e.proof_tx === 'string' && typeof e.task_id === 'string' && !seenProofTx.has(e.proof_tx)) {
          seenProofTx.set(e.proof_tx, e.task_id);
          n++;
        }
      } catch { /* skip a corrupt line */ }
    }
  } catch (e) {
    if (e.code !== 'ENOENT') console.error('loadSeenProofTx:', e.message);
  }
  return n;
}

function recordSeenProofTx(proofTx, taskId) {
  seenProofTx.set(proofTx, taskId);
  try {
    fs.appendFileSync(SEEN_FILE, JSON.stringify({ proof_tx: proofTx, task_id: taskId }) + '\n');
  } catch (e) {
    console.error('recordSeenProofTx:', e.message);
  }
}

const seenLoaded = loadSeenProofTx();

const NUMERIC_FIELDS = ['minimum', 'public_balance', 'amount', 'max_transfer', 'expiry_block', 'current_block'];
const STRING_FIELDS = ['registered_vk', 'proof_vk', 'recipient', 'condition_recipient', 'proof_tx'];

function isNumericLike(v) {
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0;
  if (typeof v === 'string') return /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(v);
  return false;
}

// Returns { decision, reason_code }. Throws nothing: malformed input is a
// REJECT, never a crash. Check order (first failing trap wins):
//   malformed -> VK mismatch -> proof reused -> balance below minimum
//   -> expired -> recipient mismatch -> amount overflow -> valid.
function decide(task) {
  const input = task && typeof task === 'object' ? task.input : null;
  if (!input || typeof input !== 'object') {
    return { decision: 'REJECT', reason_code: 'MALFORMED_TASK' };
  }
  for (const f of STRING_FIELDS) {
    if (typeof input[f] !== 'string' || input[f].length === 0) {
      return { decision: 'REJECT', reason_code: 'MALFORMED_TASK' };
    }
  }
  for (const f of NUMERIC_FIELDS) {
    if (!isNumericLike(input[f])) {
      return { decision: 'REJECT', reason_code: 'MALFORMED_TASK' };
    }
  }
  const taskId = typeof task.task_id === 'string' ? task.task_id : '';

  const registeredVk = input.registered_vk.toLowerCase();
  const proofVk = input.proof_vk.toLowerCase();
  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  const proofTx = input.proof_tx.toLowerCase();
  const prevTask = seenProofTx.get(proofTx);
  if (prevTask !== undefined && prevTask !== taskId) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  if (prevTask === undefined) recordSeenProofTx(proofTx, taskId);

  const minimum = BigInt(input.minimum);
  const publicBalance = BigInt(input.public_balance);
  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }

  // STRICT expiry: valid only while current_block < expiry_block.
  // current_block == expiry_block is EXPIRED (verified against the circuit).
  const expiryBlock = BigInt(input.expiry_block);
  const currentBlock = BigInt(input.current_block);
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }

  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }

  const amount = BigInt(input.amount);
  const maxTransfer = BigInt(input.max_transfer);
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// ---------------------------------------------------------------- proving

// Circuit inputs (verified by probing the official WASM — see
// test/probe-wasm.js): taskId, minimum, publicBalance, expiryBlock,
// currentBlock, recipient, conditionRecipient, amount, maxTransfer,
// registeredVkHash, proofVkHash, salt (private), decision (1/0).
// Public signals (13): [Poseidon(salt, taskId), registeredVkHash,
// proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
// recipient, conditionRecipient, amount, maxTransfer, decision, taskId].
function buildCircuitInput(task, decision) {
  const input = task.input;
  const salt = '0x' + crypto.randomBytes(32).toString('hex');
  return {
    registeredVkHash: String(input.registered_vk),
    proofVkHash: String(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: String(input.recipient),
    conditionRecipient: String(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id).toString(),
    salt,
  };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' timed out')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Generate a Groth16 proof for a decision and verify it locally against
// the verification key exported from the official zkey. Returns
// { proof, publicSignals, proveMs } or throws.
async function proveDecision(task, decision) {
  const circuitInput = buildCircuitInput(task, decision);
  const t0 = Date.now();
  const { proof, publicSignals } = await withTimeout(
    snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH),
    PROVE_TIMEOUT_MS,
    'fullProve'
  );
  const proveMs = Date.now() - t0;
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  if (!ok) throw new Error('local proof verification failed');
  return { proof, publicSignals, proveMs };
}

// ---------------------------------------------------------------- HTTP

function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = hmacHex(HMAC_SECRET, Buffer.from(body, 'utf8'));
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

let selfTest = { status: 'pending', detail: '' };

async function handleGatekeeper(req, res) {
  const started = Date.now();
  let rawBody;
  try {
    rawBody = await readBody(req);
  } catch (e) {
    sendJson(res, 413, { error: 'body_too_large' }, false);
    return;
  }

  // 1. Verify the HMAC against the RAW body before parsing anything.
  if (!verifySignature(rawBody, req.headers['x-agent-games-signature'])) {
    sendJson(res, 401, { error: 'bad_signature' }, false);
    return;
  }

  let task;
  try {
    task = JSON.parse(rawBody.toString('utf8'));
  } catch (e) {
    sendJson(res, 400, { error: 'bad_json' }, false);
    return;
  }

  // Preflight: the platform's signed handshake before scored tasks.
  if (task && task.type === 'agent-games.preflight.v1') {
    sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    return;
  }

  const taskId = typeof task.task_id === 'string' ? task.task_id : '';

  // 2. Idempotency: a platform retry returns the byte-identical cached body.
  if (taskId && responseCache.has(taskId)) {
    const cached = responseCache.get(taskId);
    res.writeHead(200, {
      'content-type': 'application/json',
      'x-agent-games-signature': hmacHex(HMAC_SECRET, Buffer.from(cached, 'utf8')),
    });
    res.end(cached);
    console.log(`[${new Date().toISOString()}] ${taskId} replay (cached)`);
    return;
  }

  // 3. Decide. Fail closed: anything uncertain is a REJECT.
  const { decision, reason_code } = decide(task);
  const proofTx = task.input && typeof task.input.proof_tx === 'string' ? task.input.proof_tx : '';
  const response = { decision, reason_code, proof_tx: proofTx };

  // 4. Prove the decision. REUSED-proof tasks get no proof (the rules
  // exclude them from the reliability bonus); malformed tasks cannot be
  // proven (no valid circuit inputs). An APPROVE whose proof fails falls
  // back to REJECT: the circuit is the referee, and if it refuses the
  // approval, the approval does not go out.
  let proveMs = null;
  let finalDecision = decision;
  let finalReason = reason_code;
  if (reason_code === 'PROOF_REUSED' || reason_code === 'MALFORMED_TASK') {
    // No proof to submit, by design.
  } else {
    try {
      const { proof, publicSignals, proveMs: ms } = await proveDecision(task, decision);
      response.proof = proof;
      response.public_signals = publicSignals;
      proveMs = ms;
    } catch (e) {
      if (decision === 'APPROVE') {
        // Fail closed: do not approve what cannot be proven. Try to prove
        // the REJECT instead — if the decision logic misread a trap, the
        // circuit will certify the rejection.
        try {
          const { proof, publicSignals, proveMs: ms } = await proveDecision(task, 'REJECT');
          response.proof = proof;
          response.public_signals = publicSignals;
          proveMs = ms;
          finalDecision = 'REJECT';
          finalReason = 'PROOF_FAILED';
          response.decision = 'REJECT';
          response.reason_code = 'PROOF_FAILED';
          console.error(`[${new Date().toISOString()}] ${taskId} APPROVE proof failed (${e.message}); fell back to REJECT with proof`);
        } catch (e2) {
          finalDecision = 'REJECT';
          finalReason = 'PROOF_FAILED';
          response.decision = 'REJECT';
          response.reason_code = 'PROOF_FAILED';
          console.error(`[${new Date().toISOString()}] ${taskId} APPROVE and REJECT proofs both failed (${e2.message}); REJECT without proof`);
        }
      } else {
        // A REJECT that cannot be proven is still the safe decision; the
        // response goes out without a proof (costs -2, keeps +12).
        console.error(`[${new Date().toISOString()}] ${taskId} REJECT proof failed (${e.message}); REJECT without proof`);
      }
    }
  }

  const body = sendJson(res, 200, response, true);
  if (taskId) responseCache.set(taskId, body);
  const totalMs = Date.now() - started;
  console.log(`[${new Date().toISOString()}] ${taskId} ${finalDecision} ${finalReason} totalMs=${totalMs}${proveMs !== null ? ` proveMs=${proveMs}` : ' proof=none'}`);
}

function handleHealth(req, res) {
  sendJson(res, 200, {
    ok: true,
    agent: 'proof-gatekeeper',
    hmacConfigured: HMAC_CONFIGURED,
    hmacNote: HMAC_CONFIGURED ? 'platform secret set via env' : 'TEST secret (local only)',
    taskIdMode: TASK_ID_MODE,
    selfTest,
    seenProofs: seenProofTx.size,
    cachedResponses: responseCache.size,
  }, false);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'GET' && url.pathname === '/health') return handleHealth(req, res);
  // The platform POSTs preflight + tasks to the endpoint URL as registered
  // (no path suffix), so every POST goes to the gatekeeper handler — the
  // HMAC check inside rejects anything unsigned before parsing.
  if (req.method === 'POST') {
    return handleGatekeeper(req, res).catch((e) => {
      console.error(`[${new Date().toISOString()}] handler error: ${e.message}`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' }, false);
    });
  }
  if (req.method === 'GET' && url.pathname === '/') {
    return sendJson(res, 200, { ok: true, agent: 'proof-gatekeeper' }, false);
  }
  sendJson(res, 404, { error: 'not_found' }, false);
});

// Startup self-test: prove a valid APPROVE scenario and verify it locally,
// so /health reports whether the proving path actually works.
async function selfTestProve() {
  const task = {
    task_id: 'selftest-valid',
    input: {
      registered_vk: '0x' + keccak_256(Buffer.from('selftest-vk', 'utf8')),
      proof_vk: '0x' + keccak_256(Buffer.from('selftest-vk', 'utf8')),
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: '0x' + 'de42'.padEnd(40, '0'),
      condition_recipient: '0x' + 'de42'.padEnd(40, '0'),
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xselftest',
    },
  };
  const t0 = Date.now();
  const { proveMs } = await proveDecision(task, 'APPROVE');
  selfTest = { status: 'pass', detail: `valid APPROVE proof verified locally in ${proveMs} ms (total ${Date.now() - t0} ms)` };
}

server.listen(PORT, async () => {
  console.log(`Proof Gatekeeper listening on http://127.0.0.1:${PORT} (POST /, GET /health)`);
  console.log(`HMAC: ${HMAC_CONFIGURED ? 'platform secret set via env' : 'TEST secret — local only, do not go live with this'}`);
  console.log(`taskId mode: ${TASK_ID_MODE}`);
  console.log(`seen-set: ${seenLoaded} proof(s) loaded from ${SEEN_FILE}`);
  try {
    await selfTestProve();
    console.log(`self-test: ${selfTest.detail}`);
  } catch (e) {
    selfTest = { status: 'fail', detail: e.message };
    console.error(`self-test FAILED: ${e.message}`);
  }
});

module.exports = { server, decide, proveDecision, taskIdToField, seenProofTx, responseCache };
