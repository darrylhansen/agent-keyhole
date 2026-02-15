import { describe, it, after, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { VaultStore } from '../../src/store/vault.js';
import {
  parseEnvFile,
  parseJsonFile,
} from '../../src/cli/migrate-parsers.js';
import {
  detectSecrets,
  toSecretRef,
} from '../../src/cli/migrate-detect.js';
import type { ExtractedEntry } from '../../src/cli/migrate-parsers.js';
import { TEST_SECRET, OPENAI_SECRET, WITH_SDK_ENV_CONFIG } from '../helpers/fixtures.js';

/**
 * Integration tests for the migration workflow.
 * Uses real temp files and a real VaultStore.
 */

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-migrate-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describe('migrate integration', () => {
  const dirs: string[] = [];

  after(() => {
    for (const d of dirs) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch {}
    }
  });

  it('real .env file parsed correctly', () => {
    const dir = tmpDir();
    dirs.push(dir);
    const envPath = path.join(dir, '.env');
    fs.writeFileSync(envPath, [
      '# Configuration',
      'GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE',
      'export OPENAI_API_KEY="sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK"',
      'PORT=3000',
      'NODE_ENV=production',
      '',
    ].join('\n'));

    const entries = parseEnvFile(envPath);

    assert.equal(entries.length, 4);

    // GITHUB_TOKEN
    assert.equal(entries[0].key, 'GITHUB_TOKEN');
    assert.equal(entries[0].value, TEST_SECRET);
    assert.equal(entries[0].quoteStyle, 'none');
    assert.equal(entries[0].hasExport, false);

    // OPENAI_API_KEY
    assert.equal(entries[1].key, 'OPENAI_API_KEY');
    assert.equal(entries[1].value, OPENAI_SECRET);
    assert.equal(entries[1].quoteStyle, 'double');
    assert.equal(entries[1].hasExport, true);

    // PORT
    assert.equal(entries[2].key, 'PORT');
    assert.equal(entries[2].value, '3000');

    // NODE_ENV
    assert.equal(entries[3].key, 'NODE_ENV');
    assert.equal(entries[3].value, 'production');
  });

  it('real JSON file parsed with nested keys', () => {
    const dir = tmpDir();
    dirs.push(dir);
    const jsonPath = path.join(dir, 'settings.json');
    fs.writeFileSync(jsonPath, JSON.stringify({
      api: {
        github_token: TEST_SECRET,
        port: 3000,
      },
      database: {
        password: 'db-password-long-enough-to-detect',
      },
    }, null, 2));

    const entries = parseJsonFile(jsonPath);
    const keys = entries.map(e => e.key);

    assert.ok(keys.includes('api.github_token'));
    assert.ok(keys.includes('database.password'));

    const githubEntry = entries.find(e => e.key === 'api.github_token')!;
    assert.equal(githubEntry.value, TEST_SECRET);
  });

  it('detect + import into vault → secrets accessible', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const envPath = path.join(dir, '.env');
    fs.writeFileSync(envPath, [
      `GITHUB_TOKEN=${TEST_SECRET}`,
      `OPENAI_API_KEY=${OPENAI_SECRET}`,
      'PORT=3000',
    ].join('\n'));

    // Parse and detect
    const entries = parseEnvFile(envPath);
    const candidates = detectSecrets(entries, WITH_SDK_ENV_CONFIG);
    const secrets = candidates.filter(c => c.isSecret);

    assert.ok(secrets.length >= 2, `Expected at least 2 secrets, got ${secrets.length}`);

    // Import into vault
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create('pass');

    const importEntries: [string, string][] = secrets.map(c => [
      c.secretRef,
      c.entry.value,
    ]);
    await vault.setMany(importEntries, 'pass');

    // Verify secrets accessible
    const vault2 = new VaultStore(vaultPath);
    await vault2.unlock('pass');

    for (const c of secrets) {
      const val = await vault2.get(c.secretRef);
      assert.equal(val, c.entry.value);
    }
  });

  // NOTE: The "createBackup" and "cleanupEnvFile" functions are internal to
  // src/cli/migrate.ts (not exported). These tests verify the *parser's*
  // ability to preserve quoting metadata, which is the prerequisite for
  // correct cleanup. Testing the actual file-rewriting logic would require
  // exporting createBackup, cleanupEnvFile, and cleanupJsonFile from migrate.ts.

  it('parser preserves quoteStyle=double for double-quoted values', () => {
    const dir = tmpDir();
    dirs.push(dir);
    const envPath = path.join(dir, '.env');
    fs.writeFileSync(envPath, [
      `TOKEN="${TEST_SECRET}"`,
      'PORT=3000',
    ].join('\n'));

    const entries = parseEnvFile(envPath);
    const tokenEntry = entries.find(e => e.key === 'TOKEN')!;
    assert.equal(tokenEntry.quoteStyle, 'double');
    assert.equal(tokenEntry.value, TEST_SECRET);
    assert.equal(tokenEntry.hasExport, false);
  });

  it('parser preserves quoteStyle=none for unquoted values', () => {
    const dir = tmpDir();
    dirs.push(dir);
    const envPath = path.join(dir, '.env');
    fs.writeFileSync(envPath, `TOKEN=${TEST_SECRET}\nPORT=3000\n`);

    const entries = parseEnvFile(envPath);
    const tokenEntry = entries.find(e => e.key === 'TOKEN')!;
    assert.equal(tokenEntry.quoteStyle, 'none');
    assert.equal(tokenEntry.value, TEST_SECRET);
  });

  it('setMany used for vault batch import (single disk write)', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create('pass');
    await vault.unlock('pass');

    let writeCount = 0;
    const origWrite = fs.writeFileSync;
    const writeMock = mock.fn((...args: any[]) => {
      if (typeof args[0] === 'string' && args[0].includes('keyhole.vault')) {
        writeCount++;
      }
      return (origWrite as any).apply(fs, args);
    });
    (fs as any).writeFileSync = writeMock;

    try {
      await vault.setMany(
        [
          ['github-token', TEST_SECRET],
          ['openai-key', OPENAI_SECRET],
          ['custom-key', 'custom-value-long-enough'],
        ],
        'pass',
      );
      assert.equal(writeCount, 1, 'setMany should do exactly one disk write');
    } finally {
      (fs as any).writeFileSync = origWrite;
    }
  });

  it('service matching via sdk_env', () => {
    const entries: ExtractedEntry[] = [
      {
        key: 'GITHUB_TOKEN',
        value: TEST_SECRET,
        file: '.env',
        line: 1,
        rawLine: `GITHUB_TOKEN=${TEST_SECRET}`,
        quoteStyle: 'none',
        hasExport: false,
        format: 'env',
      },
    ];

    const results = detectSecrets(entries, WITH_SDK_ENV_CONFIG);
    const secret = results.find(r => r.isSecret);
    assert.ok(secret);
    assert.equal(secret.matchedService, 'github');
    assert.equal(secret.secretRef, 'github-token');
  });
});
