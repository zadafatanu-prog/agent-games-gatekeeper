// scripts/fetch-circuits.js — download the official gatekeeper circuit artifacts
// (wasm + zkey) and verify SHA-256. Idempotent: skips files that already exist
// with the correct hash. Runs automatically on `npm install` (postinstall) and
// during the Render build. The artifacts are binary, so they are NOT committed
// to the repo; they are fetched from the official Agent Games site at build time.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const ARTIFACTS = [
  {
    name: 'gatekeeper.wasm',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm',
    sha256: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f',
  },
  {
    name: 'gatekeeper_final.zkey',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey',
    sha256: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d',
  },
];

const DIR = path.join(__dirname, '..', 'circuits');

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
    }).on('error', reject);
  });
}

async function main() {
  fs.mkdirSync(DIR, { recursive: true });
  for (const a of ARTIFACTS) {
    const dest = path.join(DIR, a.name);
    if (fs.existsSync(dest) && sha256File(dest) === a.sha256) {
      console.log(`fetch-circuits: ${a.name} already present, hash OK`);
      continue;
    }
    console.log(`fetch-circuits: downloading ${a.name} ...`);
    await download(a.url, dest);
    const got = sha256File(dest);
    if (got !== a.sha256) {
      fs.unlinkSync(dest);
      throw new Error(`SHA-256 mismatch for ${a.name}: got ${got}, want ${a.sha256}`);
    }
    console.log(`fetch-circuits: ${a.name} OK (${fs.statSync(dest).size} bytes, hash verified)`);
  }
  console.log('fetch-circuits: all artifacts verified');
}

main().catch((e) => { console.error('fetch-circuits: FAILED:', e.message); process.exit(1); });
