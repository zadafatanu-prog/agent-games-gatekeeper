# Proof Gatekeeper — zkVerify Agent Games Season 01

A local, working Proof Gatekeeper agent for the zkVerify Agent Games
(Season 01, 21 Oct – 21 Nov 2026). It receives a signed task envelope,
decides APPROVE or REJECT by walking the documented 7-trap checklist,
generates a Groth16 proof of the decision with the tournament's official
gatekeeper circuit, verifies that proof locally, and returns a signed
response — all inside the 60-second deadline.

**Status: local build, tested end to end. Account registered (handle
`genou`). Deployment to Render in progress — see below.**

## How to run

```bash
cd ~/workspace/agent-games/gatekeeper
npm install            # snarkjs 0.7.6, js-sha3, poseidon-lite
node server.js         # listens on http://127.0.0.1:8787
```

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8787` | Local port |
| `AGENT_GAMES_HMAC_SECRET` | built-in TEST secret | Platform secret from registration (Rotate Secret). Without it the server uses a test-only placeholder and `/health` reports `hmacConfigured: false`. |
| `GATEKEEPER_TASK_ID_MODE` | `keccak` | How `task_id` maps to a circuit field element: `keccak` (keccak256 mod p), `numeric`, or `hex`. Unconfirmed against the platform — see open items. |

Endpoints:

- `POST /gatekeeper` — the agent endpoint. Verifies the
  `x-agent-games-signature` HMAC-SHA256 header against the raw body
  before parsing; answers preflight (`{"type":"agent-games.preflight.v1"}`)
  with `{ok:true, protocolVersion:"v1"}`; otherwise decides, proves,
  and returns `{decision, reason_code, proof_tx, proof, public_signals}`,
  signed with the same HMAC header over the raw response body.
- `GET /health` — `{ok, hmacConfigured, taskIdMode, selfTest,
  seenProofs, cachedResponses}`. The server runs a proof self-test at
  startup (a valid APPROVE proof, verified locally) and reports it here.

## How it decides

Check order (first failing trap wins). Anything uncertain is a REJECT —
the agent never approves by default.

| Order | Check | reason_code |
| --- | --- | --- |
| 1 | Missing/invalid fields | `MALFORMED_TASK` (no proof — no valid circuit inputs) |
| 2 | `proof_vk != registered_vk` (case-insensitive) | `VK_SUBSTITUTION` |
| 3 | `proof_tx` already seen under a *different* `task_id` | `PROOF_REUSED` (no proof — the rules exclude these from the reliability bonus) |
| 4 | `public_balance < minimum` | `THRESHOLD_MISMATCH` |
| 5 | `current_block >= expiry_block` | `EXPIRED_CONDITION` |
| 6 | `recipient != condition_recipient` (case-insensitive) | `RECIPIENT_MISMATCH` |
| 7 | `amount > max_transfer` | `AMOUNT_OVERFLOW` |
| — | All checks pass | `VALID_CONDITION` → APPROVE |

Boundary rules (verified against the circuit, see the trap matrix):
`public_balance == minimum` is VALID; `amount == max_transfer` is
VALID; expiry is STRICT — `current_block == expiry_block` is EXPIRED
(valid only while `current_block < expiry_block`).

Fail-closed behavior:

- An APPROVE whose proof generation fails does not go out. The server
  tries to prove the REJECT instead (if the decision logic misread a
  trap, the circuit certifies the rejection) and returns REJECT with
  reason `PROOF_FAILED`. If the REJECT proof also fails, it returns
  REJECT without a proof.
- A REJECT whose proof fails still goes out as REJECT without a proof
  (the safe decision; costs −2 for the missing proof, keeps +12).
- Proof generation has a 30-second internal timeout; the server never
  hangs — an internal error returns a 500, not a timeout.
- Responses are cached by `task_id`: a platform retry returns the
  byte-identical cached body without re-deciding (so a retry of the
  same task is never misread as a proof reuse).

## The 13 circuit inputs — found and verified

The site publishes the circuit files but not the source or the input
signal names. I found the names by probing the compiled WASM itself
(`test/probe-wasm.js`): Circom 2 WASM resolves input signals by FNV-1a
64-bit hash of the name, and exports `getInputSignalSize(hash)`. The
probe hashes each candidate name and asks the WASM whether it exists.

Verified results (circom 2.2.3, `getInputSize() = 13`,
`getWitnessSize() = 647`, `nPublic = 13` from the exported vk):

| # | Signal | Role | Source |
| --- | --- | --- | --- |
| 1 | `taskId` | binds the proof to one task | keccak256(task_id) mod p |
| 2 | `minimum` | required minimum balance | envelope `minimum` |
| 3 | `publicBalance` | balance disclosed in the proof | envelope `public_balance` |
| 4 | `expiryBlock` | condition expiry (block height) | envelope `expiry_block` |
| 5 | `currentBlock` | block height now | envelope `current_block` |
| 6 | `recipient` | where the money would go | envelope `recipient` |
| 7 | `conditionRecipient` | where the condition says it must go | envelope `condition_recipient` |
| 8 | `amount` | requested payment | envelope `amount` |
| 9 | `maxTransfer` | single-transfer cap | envelope `max_transfer` |
| 10 | `registeredVkHash` | the VK the condition registered | envelope `registered_vk` |
| 11 | `proofVkHash` | the VK the proof actually used | envelope `proof_vk` |
| 12 | `salt` | private nonce (the only private input) | random 32 bytes per proof |
| 13 | `decision` | 1 = approve, 0 = reject | the agent's decision |

How the probe was validated: all 13 names return size 1, and 45
plausible decoy names (`task_id`, `balance`, `vk`, `nonce`,
`decision_flag`, `proof_tx`, …) all return size 0 — the probe
discriminates, and 13 found == `getInputSize()` 13, so there are no
hidden inputs. (Note: in this WASM build a missing signal returns size
0, not a negative value; snarkjs would reject such a name as "too many
values".)

Public signals (13, in order): `[commitment, registeredVkHash,
proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`.
The first signal is the circuit's output, not an input: I verified
with poseidon-lite that **`public[0] = Poseidon(salt, taskId)`** —
the commitment binds the private salt to the task id. Changing the
salt changes it; changing the decision, amount, or recipient does not.

What the circuit enforces (verified by the trap matrix): **decision
must equal the computed verdict.** Approve if and only if every check
passes. A dishonest decision fails at witness generation with
`Assert Failed. Error in template GatekeeperEvaluation_79 line: 102` —
no proof exists for it. The circuit does NOT check proof reuse (no
reuse input) and does NOT check that the VK hashes equal any
particular registered value (it only checks the two are equal) — both
are the gatekeeper's off-circuit job. Note the envelope's
`registered_vk` is the *payment condition's* VK, not the gatekeeper
circuit's vkHash from `/api/circuit-info`; comparing them would be a
category error and would reject every valid task.

## Circuit artifacts (verified)

Downloaded from the official site, SHA-256 checked against the values
published by another participant (they match):

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `circuits/gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `circuits/gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

`circuits/verification_key.json` was exported from the zkey with
`snarkjs zkey export verificationkey` (curve bn128, protocol groth16,
nPublic 13). Registered gatekeeper vkHash from
`/api/circuit-info`: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

## Test results

Run everything with `npm test` (or each file directly). All runs below
were executed locally on 2026-11-16.

### 1. WASM probe — `node test/probe-wasm.js`

13/13 input names found, 45/45 decoys rejected, count matches
`getInputSize()`. **PASS.**

### 2. Proof smoke test — `node test/proof-smoke.js`

Valid scenario (sample numbers, matching VKs): fullProve 1164 ms,
verify true (157 ms), public-signal order matches the documented
order, `Poseidon(salt, taskId) == public[0]` confirmed. **PASS.**

### 3. Trap matrix — `node test/trap-matrix.js` — 18/18 PASS

Every circuit-checkable variety, both decisions:

| Case | decision=1 | decision=0 |
| --- | --- | --- |
| valid condition | proves + verifies | refused (assert line 102) |
| VK_SUBSTITUTION | refused | proves + verifies |
| THRESHOLD_MISMATCH | refused | proves + verifies |
| EXPIRED_CONDITION | refused | proves + verifies |
| RECIPIENT_MISMATCH | refused | proves + verifies |
| AMOUNT_OVERFLOW | refused | proves + verifies |
| boundary: balance == minimum | proves + verifies (VALID) | refused |
| boundary: amount == max | proves + verifies (VALID) | refused |
| boundary: current == expiry | refused (EXPIRED) | proves + verifies |

Prove timings (successful): min 359 ms, max 1373 ms, mean 539 ms —
against a 60,000 ms deadline.

### 4. HTTP end-to-end — `node test/http-test.js` — 37/37 PASS

Starts the real server and drives it with signed requests:

- Health + startup self-test pass; valid task → APPROVE +
  locally-verifying proof, 449 ms total.
- Published sample as-is (VK mismatch) → REJECT / VK_SUBSTITUTION +
  verifying proof.
- THRESHOLD_MISMATCH, EXPIRED_CONDITION, RECIPIENT_MISMATCH,
  AMOUNT_OVERFLOW → correct REJECT + reason code + verifying proof.
- All three boundaries correct (balance == minimum APPROVE,
  amount == max APPROVE, current == expiry REJECT).
- PROOF_REUSED → REJECT, no proof attached.
- Same-task retry → byte-identical cached body.
- Wrong HMAC → 401; missing HMAC → 401; tampered body with the
  original signature → 401.
- Malformed task → REJECT / MALFORMED_TASK, no proof.
- Preflight → `{ok:true, protocolVersion:"v1"}`, signed.
- Every response carries a valid `x-agent-games-signature`.
- Unknown route → 404.

### 5. vkHash reproduction — `node test/vkhash-check.js` — NOT REPRODUCED

8 serialization variants tried (keccak256/SHA-256 over compact,
indented, and sorted-keys JSON; flattened curve points; IC-only;
G2 limbs swapped) — none matches the registered vkHash
`0x6b79c6…d77b0`. Another participant tried 12 further variants with
the same result. The platform (zkVerify/Kurier) computes the
registered hash over its own canonical serialization. This does not
affect local proof generation (proofs verify against the exported
vk), but it is an open item for going live: the platform re-verifies
proofs against *its* registered key, so the first practice task is
the real check that our proofs are accepted.

## Files

```
server.js                  the agent (single file, no framework)
package.json               snarkjs 0.7.6, js-sha3, poseidon-lite
circuits/
  gatekeeper.wasm          official circuit WASM (SHA-256 verified)
  gatekeeper_final.zkey    official proving key (SHA-256 verified)
  verification_key.json    exported from the zkey with snarkjs
test/
  probe-wasm.js            finds the 13 input names from the WASM
  proof-smoke.js           valid scenario + public-signal order + Poseidon commitment
  trap-matrix.js           all 7 varieties x both decisions vs the circuit
  http-test.js             end-to-end HTTP test (37 checks)
  vkhash-check.js          vkHash reproduction attempt (open item)
```

## What is still needed to go live

1. **Registration**: DONE — account registered 2026-11-16 as handle
   `genou` (SIWE). Still needed: connect a GitHub account and a wallet
   for prizes (dashboard), register the agent endpoint once the public
   URL exists.
2. **Real HMAC secret**: from the dashboard (Rotate Secret), set as
   `AGENT_GAMES_HMAC_SECRET`. The built-in test secret must never go
   live. The HMAC format (bare hex vs `sha256=` prefix) is assumed
   from the docs, not confirmed — preflight is the verification step.
3. **Public HTTPS endpoint**: the platform requires a public HTTPS
   address (no localhost, no custom ports). This VM has no public IP
   and its egress proxy blocks the free tunnel services (measured by
   another participant: tunnelmole 502, trycloudflare 403). Host the
   server on a PC/VPS with unrestricted egress, or use Tailscale
   Funnel / a named Cloudflare Tunnel / free hosting. Note the rules:
   free-tier hosting that sleeps after inactivity will cost tasks
   (an offline agent forfeits the task).
4. **Practice task first**: run the signed preflight and at least one
   practice task before the first scored round. This confirms (a) the
   HMAC format, (b) the `taskId` mapping (keccak256 mod p is the
   default; switch `GATEKEEPER_TASK_ID_MODE` to `numeric` or `hex` if
   the platform rejects the proof), and (c) that proofs generated
   here are accepted against the platform's registered key (see the
   vkHash open item above).
5. **Rounds**: scored rounds run 13–20 Nov 2026, 8 tasks per agent
   per round, 17:30–03:30 WIB. Rounds 1–3 are already over; Round 4
   opens 16 Nov 17:30 WIB. Entries lock while a round is open.
6. **Persistence note**: the seen-proof set and the response cache
   live in memory. A server restart loses them — a proof_tx seen
   before a restart could be approved again after it. For a
   multi-day tournament, persist the seen-set to disk (a small
   append-only file) before going live.

## References

- Official field guide: https://agentgames.zkverify.io/build
- Event page: https://agentgames.zkverify.io/events/proof-gatekeeper
- Rules: https://agentgames.zkverify.io/rules
- Circuit info (vkHash): https://agentgames.zkverify.io/api/circuit-info
- Reference builds consulted (findings re-verified independently;
  no code copied verbatim): the Medium article by @sidik666 (WASM
  probing method, 13 inputs, Poseidon commitment), the dev.to
  article by @bangkitnovendy11 (server design, vkHash gap), the
  dev.to article by @jotri (cheat battery), and the public repo
  subastian1998/agent-games-season-01 (taskId mapping options,
  preflight shape, hosting caveats).
