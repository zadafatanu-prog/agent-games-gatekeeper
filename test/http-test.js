// HTTP end-to-end test: starts the real server in-process on a test port
// and drives it with signed requests. Covers the sample scenario, every
// trap variety with its reason code, proof-reuse, idempotent replay,
// HMAC acceptance/rejection, malformed input, preflight, response
// signing, and timing. Run: node test/http-test.js
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const TEST_PORT = 18787;
const TEST_SECRET = 'http-test-secret-not-for-production';
process.env.PORT = String(TEST_PORT);
process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;

const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');
const { server } = require('../server');

const DIR = path.join(__dirname, '..');
const VK = JSON.parse(fs.readFileSync(path.join(DIR, 'circuits', 'verification_key.json'), 'utf8'));

const VK_A = '0x' + keccak_256(Buffer.from('vk-a', 'utf8'));
const VK_B = '0x' + keccak_256(Buffer.from('vk-b', 'utf8'));
const ADDR_A = '0x' + 'de42'.padEnd(40, '0');
const ADDR_B = '0x' + 'beef'.padEnd(40, '0');

let pass = 0;
let fail = 0;
function check(name, ok, detail = '') {
  if (ok) pass++; else fail++;
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}

function sign(body) {
  return crypto.createHmac('sha256', TEST_SECRET).update(Buffer.from(body, 'utf8')).digest('hex');
}

function request({ method, path: p, body, signature, rawHeaders = {} }) {
  return new Promise((resolve, reject) => {
    const headers = { 'content-type': 'application/json', ...rawHeaders };
    if (signature !== undefined) headers['x-agent-games-signature'] = signature;
    const req = http.request({ host: '127.0.0.1', port: TEST_PORT, path: p, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function task(taskId, inputOverrides = {}, envelopeOverrides = {}) {
  return JSON.stringify({
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: '2026-11-16T00:00:00Z',
    deadline_at: '2026-11-16T00:01:00Z',
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR_A,
      condition_recipient: ADDR_A,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0x' + keccak_256(Buffer.from('proof-' + taskId, 'utf8')),
      ...inputOverrides,
    },
    ...envelopeOverrides,
  });
}

async function verifyProofField(res, label) {
  let parsed;
  try { parsed = JSON.parse(res.body); } catch { check(label, false, 'unparseable body'); return null; }
  if (!parsed.proof || !parsed.public_signals) {
    check(label, false, 'missing proof/public_signals');
    return parsed;
  }
  const ok = await snarkjs.groth16.verify(VK, parsed.public_signals, parsed.proof);
  check(label, ok === true, ok ? 'proof verifies against exported vk' : 'proof DOES NOT verify');
  return parsed;
}

function verifyResponseSignature(res, label) {
  const sig = res.headers['x-agent-games-signature'];
  if (!sig) { check(label, false, 'no x-agent-games-signature header'); return; }
  const expected = sign(res.body);
  const ok = sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expected, 'utf8'));
  check(label, ok, ok ? 'response signature valid' : 'response signature INVALID');
}

async function waitForHealth() {
  for (let i = 0; i < 30; i++) {
    try {
      const res = await request({ method: 'GET', path: '/health' });
      const h = JSON.parse(res.body);
      if (h.selfTest && h.selfTest.status !== 'pending') return h;
    } catch { /* server not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server did not become healthy in time');
}

async function main() {
  const health = await waitForHealth();
  check('GET /health returns ok', health.ok === true);
  check('health reports hmacConfigured', health.hmacConfigured === true);
  check('startup self-test passes', health.selfTest.status === 'pass', health.selfTest.detail);

  // (a) Sample scenario, valid -> APPROVE + verifying proof.
  const t0 = Date.now();
  const validBody = task('gk_http_valid');
  const validRes = await request({ method: 'POST', path: '/gatekeeper', body: validBody, signature: sign(validBody) });
  const validMs = Date.now() - t0;
  check('valid task -> HTTP 200', validRes.status === 200, `status=${validRes.status}`);
  const validParsed = JSON.parse(validRes.body);
  check('valid task -> APPROVE', validParsed.decision === 'APPROVE', `decision=${validParsed.decision}`);
  check('valid task -> VALID_CONDITION', validParsed.reason_code === 'VALID_CONDITION');
  check('valid task -> echoes proof_tx', typeof validParsed.proof_tx === 'string' && validParsed.proof_tx.startsWith('0x'));
  await verifyProofField(validRes, 'valid task -> proof verifies');
  verifyResponseSignature(validRes, 'valid task -> response is signed');
  check('valid task -> total time well under 60s', validMs < 10000, `${validMs} ms`);

  // Sample scenario as published (VK mismatch) -> REJECT / VK_SUBSTITUTION.
  const sampleBody = task('gk_http_sample', { proof_vk: VK_B });
  const sampleRes = await request({ method: 'POST', path: '/gatekeeper', body: sampleBody, signature: sign(sampleBody) });
  const sampleParsed = JSON.parse(sampleRes.body);
  check('published sample (VK mismatch) -> REJECT', sampleParsed.decision === 'REJECT');
  check('published sample -> VK_SUBSTITUTION', sampleParsed.reason_code === 'VK_SUBSTITUTION');
  await verifyProofField(sampleRes, 'published sample -> REJECT proof verifies');

  // The remaining trap varieties.
  const traps = [
    ['THRESHOLD_MISMATCH', { public_balance: '900' }],
    ['EXPIRED_CONDITION', { current_block: 19843000 }],
    ['RECIPIENT_MISMATCH', { recipient: ADDR_B }],
    ['AMOUNT_OVERFLOW', { amount: '1500' }],
  ];
  for (const [code, overrides] of traps) {
    const b = task('gk_http_' + code.toLowerCase(), overrides);
    const r = await request({ method: 'POST', path: '/gatekeeper', body: b, signature: sign(b) });
    const p = JSON.parse(r.body);
    check(`${code} -> REJECT`, p.decision === 'REJECT' && p.reason_code === code, `got ${p.decision}/${p.reason_code}`);
    await verifyProofField(r, `${code} -> REJECT proof verifies`);
  }

  // Boundary: balance == minimum and amount == max are VALID.
  const b1 = task('gk_http_bnd_bal', { public_balance: '1000' });
  const r1 = await request({ method: 'POST', path: '/gatekeeper', body: b1, signature: sign(b1) });
  check('boundary balance == minimum -> APPROVE', JSON.parse(r1.body).decision === 'APPROVE');
  const b2 = task('gk_http_bnd_amt', { amount: '1000' });
  const r2 = await request({ method: 'POST', path: '/gatekeeper', body: b2, signature: sign(b2) });
  check('boundary amount == max -> APPROVE', JSON.parse(r2.body).decision === 'APPROVE');
  const b3 = task('gk_http_bnd_exp', { current_block: 19842201 });
  const r3 = await request({ method: 'POST', path: '/gatekeeper', body: b3, signature: sign(b3) });
  const p3 = JSON.parse(r3.body);
  check('boundary current == expiry -> REJECT/EXPIRED', p3.decision === 'REJECT' && p3.reason_code === 'EXPIRED_CONDITION');

  // PROOF_REUSED: same proof_tx under a different task_id.
  const sharedTx = '0x' + keccak_256(Buffer.from('shared-proof-tx', 'utf8'));
  const first = task('gk_http_reuse_1', { proof_tx: sharedTx });
  const firstRes = await request({ method: 'POST', path: '/gatekeeper', body: first, signature: sign(first) });
  check('reuse setup: first use -> APPROVE', JSON.parse(firstRes.body).decision === 'APPROVE');
  const second = task('gk_http_reuse_2', { proof_tx: sharedTx });
  const secondRes = await request({ method: 'POST', path: '/gatekeeper', body: second, signature: sign(second) });
  const secondParsed = JSON.parse(secondRes.body);
  check('PROOF_REUSED -> REJECT', secondParsed.decision === 'REJECT' && secondParsed.reason_code === 'PROOF_REUSED',
    `got ${secondParsed.decision}/${secondParsed.reason_code}`);
  check('PROOF_REUSED -> no proof attached', !secondParsed.proof && !secondParsed.public_signals);

  // Idempotent replay: same task_id returns the byte-identical body.
  const replayRes = await request({ method: 'POST', path: '/gatekeeper', body: validBody, signature: sign(validBody) });
  check('same task_id replay -> byte-identical body', replayRes.body === validRes.body);
  check('same task_id replay -> HTTP 200', replayRes.status === 200);

  // HMAC: wrong signature -> 401, missing signature -> 401.
  const badSig = await request({ method: 'POST', path: '/gatekeeper', body: validBody, signature: '0'.repeat(64) });
  check('wrong HMAC -> 401', badSig.status === 401, `status=${badSig.status}`);
  const noSig = await request({ method: 'POST', path: '/gatekeeper', body: validBody });
  check('missing HMAC -> 401', noSig.status === 401, `status=${noSig.status}`);
  // Tampered body with the original signature -> 401.
  const tampered = validBody.replace('1460', '1461');
  const tamperedRes = await request({ method: 'POST', path: '/gatekeeper', body: tampered, signature: sign(validBody) });
  check('tampered body + original signature -> 401', tamperedRes.status === 401, `status=${tamperedRes.status}`);

  // Malformed task -> REJECT / MALFORMED_TASK, no proof.
  const malformed = JSON.stringify({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_http_malformed', input: { minimum: '1000' } });
  const malformedRes = await request({ method: 'POST', path: '/gatekeeper', body: malformed, signature: sign(malformed) });
  const malformedParsed = JSON.parse(malformedRes.body);
  check('malformed task -> REJECT/MALFORMED_TASK', malformedParsed.decision === 'REJECT' && malformedParsed.reason_code === 'MALFORMED_TASK',
    `got ${malformedParsed.decision}/${malformedParsed.reason_code}`);
  check('malformed task -> no proof attached', !malformedParsed.proof);

  // Preflight.
  const preflight = JSON.stringify({ type: 'agent-games.preflight.v1' });
  const preflightRes = await request({ method: 'POST', path: '/gatekeeper', body: preflight, signature: sign(preflight) });
  const preflightParsed = JSON.parse(preflightRes.body);
  check('preflight -> {ok:true, protocolVersion:v1}', preflightRes.status === 200 && preflightParsed.ok === true && preflightParsed.protocolVersion === 'v1');
  verifyResponseSignature(preflightRes, 'preflight -> response is signed');

  // Unknown route -> 404.
  const notFound = await request({ method: 'GET', path: '/nope' });
  check('unknown route -> 404', notFound.status === 404);

  console.log(`\n${pass} passed, ${fail} failed`);
  server.close();
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); try { server.close(); } catch {} process.exit(1); });
