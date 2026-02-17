/**
 * Masking Trap — Manual validation of the 4-layer response masking pipeline.
 *
 * Starts a local mock HTTP server on port 9999 that returns a response
 * designed to trigger (or intentionally skip) each masking layer.
 * Then uses the public createKeyhole() API to proxy a request through
 * the sidecar, and checks that masking behaves correctly.
 *
 * Usage:
 *   npx tsx test/manual/masking-trap.ts
 *
 * Prerequisites:
 *   - npm run build (so src/ imports resolve)
 *   - Secret store has 'local-mock-token' set to the KNOWN_SECRET below
 *     Vault:    npx keyhole vault add local-mock-token
 *     Keychain: npx keyhole add local-mock-token
 */

import http from 'http';
import fs from 'fs';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { createKeyhole } from '../../src/index.js';
import type { Keyhole } from '../../src/index.js';

// ── Known secret (must match what's stored in the vault/keychain) ──

const KNOWN_SECRET = 'ghp_m4nualTr4pS3cret9K7xR2pL5wQ8vF0bN1c';

// ── Inline promptSecret (raw-mode stdin, no echo) ──

async function promptSecret(prompt: string): Promise<string> {
  process.stderr.write(prompt);

  if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
  }

  return new Promise((resolve) => {
    let input = '';

    const cleanup = () => {
      process.stdin.removeListener('data', onData);
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      process.stdin.pause();
    };

    const onData = (data: Buffer) => {
      for (const byte of data) {
        if (byte === 0x0d || byte === 0x0a) {
          cleanup();
          process.stderr.write('\n');
          resolve(input);
          return;
        } else if (byte === 0x03) {
          cleanup();
          process.stderr.write('\n');
          process.exit(130);
        } else if (byte === 0x7f || byte === 0x08) {
          input = input.slice(0, -1);
        } else if (byte >= 0x20) {
          input += String.fromCharCode(byte);
        }
      }
    };

    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

// ── Mock upstream server ──

const MOCK_ACCESS_TOKEN = crypto.randomBytes(32).toString('hex'); // 64-char high-entropy
const MOCK_SESSION_ID = crypto.randomUUID();                       // UUID — should be preserved
const MOCK_INTERNAL_TOKEN = 'ghp_internalTokenThatMatchesPattern1234567';

function createMockServer(): http.Server {
  return http.createServer((req, res) => {
    if (req.url === '/api/data') {
      const body = JSON.stringify({
        user: 'test-agent',
        access_token: MOCK_ACCESS_TOKEN,
        session_id: MOCK_SESSION_ID,
        clone_url: `https://github.com/repo.git?token=${KNOWN_SECRET}`,
        debug: {
          internal_token: MOCK_INTERNAL_TOKEN,
        },
        token_type: 'bearer',
        expires_in: 3600,
      });

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=abc123; Path=/; HttpOnly',
        'X-Api-Key': 'internal-key-value-should-be-scrubbed',
      });
      res.end(body);
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  });
}

// ── Check helpers ──

interface CheckResult {
  layer: string;
  name: string;
  pass: boolean;
  detail: string;
}

const results: CheckResult[] = [];

function check(layer: string, name: string, pass: boolean, detail: string) {
  results.push({ layer, name, pass, detail });
}

// ── Main ──

async function main() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const configPath = path.resolve(__dirname, 'fixtures/sample-keyhole.yaml');
  const vaultPath = path.resolve('.keyhole.vault');

  console.error('=== Masking Trap — Manual Validation ===\n');

  // Start mock server
  const server = createMockServer();
  await new Promise<void>((resolve) => server.listen(9999, '127.0.0.1', resolve));
  console.error('Mock server listening on http://127.0.0.1:9999\n');

  let keyhole: Keyhole | null = null;

  try {
    // Detect store and create keyhole instance
    const useVault = fs.existsSync(vaultPath);

    if (useVault) {
      console.error('Detected vault store at', vaultPath);
      const passphrase = await promptSecret('Vault passphrase: ');

      keyhole = await createKeyhole({
        config: configPath,
        vaultPath,
        vaultPassphrase: passphrase,
      });
    } else {
      console.error('No vault found — using OS keychain');
      keyhole = await createKeyhole({
        config: configPath,
      });
    }

    console.error('Sidecar started, creating client for local-mock...\n');

    // Make request through sidecar
    const client = keyhole.createClient('local-mock');
    const response = await client('/api/data');
    const headers = Object.fromEntries(response.headers.entries());
    const body = await response.json() as Record<string, any>;

    // ── L1: Header Scrubbing ──

    check('L1', 'set-cookie scrubbed',
      !('set-cookie' in headers),
      `set-cookie ${('set-cookie' in headers) ? 'PRESENT (leaked)' : 'absent (scrubbed)'}`,
    );

    check('L1', 'x-api-key scrubbed',
      !('x-api-key' in headers),
      `x-api-key ${('x-api-key' in headers) ? 'PRESENT (leaked)' : 'absent (scrubbed)'}`,
    );

    check('L1', 'content-type preserved',
      'content-type' in headers,
      `content-type ${('content-type' in headers) ? 'present' : 'MISSING'}`,
    );

    // ── L2: Known-Secret Exact Match ──

    const cloneUrl = String(body.clone_url || '');
    check('L2', 'clone_url does not contain known secret',
      !cloneUrl.includes(KNOWN_SECRET),
      cloneUrl.includes(KNOWN_SECRET)
        ? `LEAKED: clone_url contains ${KNOWN_SECRET}`
        : `clone_url redacted: ${cloneUrl}`,
    );

    // ── L3: Heuristic Detection ──

    const accessToken = String(body.access_token || '');
    check('L3', 'access_token redacted (high entropy + suspicious key)',
      accessToken !== MOCK_ACCESS_TOKEN,
      accessToken === MOCK_ACCESS_TOKEN
        ? `LEAKED: access_token = ${accessToken.slice(0, 16)}...`
        : `access_token redacted: ${accessToken}`,
    );

    const sessionId = String(body.session_id || '');
    check('L3', 'session_id preserved (UUID excluded from heuristic)',
      sessionId === MOCK_SESSION_ID,
      sessionId === MOCK_SESSION_ID
        ? `session_id preserved: ${sessionId}`
        : `REDACTED (should be preserved): ${sessionId}`,
    );

    const tokenType = String(body.token_type || '');
    check('L3', 'token_type preserved (too short)',
      tokenType === 'bearer',
      tokenType === 'bearer'
        ? 'token_type preserved: bearer'
        : `REDACTED (should be preserved): ${tokenType}`,
    );

    const expiresIn = body.expires_in;
    check('L3', 'expires_in preserved (number, not a string)',
      expiresIn === 3600,
      expiresIn === 3600
        ? 'expires_in preserved: 3600'
        : `CHANGED: ${JSON.stringify(expiresIn)}`,
    );

    // ── L4: JSON Path Redaction ──

    const internalToken = String(body.debug?.internal_token || '');
    check('L4', 'debug.internal_token redacted (json_path match)',
      internalToken !== MOCK_INTERNAL_TOKEN,
      internalToken === MOCK_INTERNAL_TOKEN
        ? `LEAKED: debug.internal_token = ${internalToken}`
        : `debug.internal_token redacted: ${internalToken}`,
    );

    // ── Report ──

    console.log('\n=== Masking Trap Results ===\n');

    let allPass = true;
    for (const r of results) {
      const status = r.pass ? 'PASS' : 'FAIL';
      const icon = r.pass ? ' ' : '!';
      console.log(`[${status}] ${icon} ${r.layer}: ${r.name}`);
      console.log(`        ${r.detail}`);
      if (!r.pass) allPass = false;
    }

    console.log(`\n${results.filter(r => r.pass).length}/${results.length} checks passed.`);

    if (allPass) {
      console.log('\nAll masking layers validated successfully.');
    } else {
      console.error('\nSome checks FAILED — review output above.');
    }

    process.exitCode = allPass ? 0 : 1;
  } catch (err) {
    console.error('\nFatal error:', err);
    process.exitCode = 2;
  } finally {
    if (keyhole) {
      await keyhole.shutdown();
    }
    server.close();
  }
}

main();
