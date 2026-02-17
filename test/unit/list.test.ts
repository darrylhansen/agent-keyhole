import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { VaultStore } from '../../src/store/vault.js';

/**
 * Integration tests for the list command, focused on orphaned secrets display.
 * Uses real temp files + vault, spawns the CLI to test end-to-end output.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const BIN = path.join(ROOT, 'bin/keyhole.js');
const PASSPHRASE = 'testpassphrase1234';

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-list-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runList(cwd: string, configPath: string, vaultPath: string, passphrase?: string): string {
  const result = spawnSync(
    process.execPath,
    [BIN, 'list', '--config', configPath, '--vault', vaultPath],
    {
      input: passphrase ? passphrase + '\n' : '\n',
      cwd,
      encoding: 'utf-8',
      timeout: 10000,
    }
  );
  return result.stderr;
}

// Minimal keyhole.yaml with one service
const MINIMAL_CONFIG = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
`;

describe('list command — orphaned secrets', () => {
  const dirs: string[] = [];

  after(() => {
    for (const d of dirs) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch {}
    }
  });

  it('shows orphaned secrets not matching any service', async () => {
    const dir = tmpDir();
    dirs.push(dir);

    // Write config with 1 service
    const configPath = path.join(dir, 'keyhole.yaml');
    fs.writeFileSync(configPath, MINIMAL_CONFIG);

    // Create vault with 3 secrets: 1 matching + 2 orphaned
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create(PASSPHRASE);
    await vault.setMany([
      ['github-token', 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE'],
      ['openai-api-key', 'sk-proj-FAKEFAKEFAKEFAKEFAKE'],
      ['stripe-secret-key', 'sk_test_FAKEFAKEFAKEFAKE'],
    ], PASSPHRASE);

    const output = runList(dir, configPath, vaultPath, PASSPHRASE);

    // Configured service should show as stored
    assert.ok(output.includes('github'), 'should show github service');
    assert.ok(output.includes('+ stored'), 'github-token should be stored');

    // Orphaned secrets should appear
    assert.ok(
      output.includes('Additional secrets in store'),
      'should show orphaned secrets section'
    );
    assert.ok(output.includes('openai-api-key'), 'should show openai-api-key as orphaned');
    assert.ok(output.includes('stripe-secret-key'), 'should show stripe-secret-key as orphaned');

    // Summary should mention orphaned count
    assert.ok(output.includes('2 additional secret(s)'), 'should show orphaned count');
  });

  it('no orphaned section when all secrets match services', async () => {
    const dir = tmpDir();
    dirs.push(dir);

    const configPath = path.join(dir, 'keyhole.yaml');
    fs.writeFileSync(configPath, MINIMAL_CONFIG);

    // Vault has only the matching secret
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create(PASSPHRASE);
    await vault.setMany([
      ['github-token', 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE'],
    ], PASSPHRASE);

    const output = runList(dir, configPath, vaultPath, PASSPHRASE);

    assert.ok(output.includes('+ stored'), 'github-token should be stored');
    assert.ok(
      !output.includes('Additional secrets in store'),
      'should NOT show orphaned section'
    );
  });

  it('vault locked → no orphaned section shown', async () => {
    const dir = tmpDir();
    dirs.push(dir);

    const configPath = path.join(dir, 'keyhole.yaml');
    fs.writeFileSync(configPath, MINIMAL_CONFIG);

    // Vault has orphaned secrets but we'll provide wrong passphrase
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create(PASSPHRASE);
    await vault.setMany([
      ['github-token', 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE'],
      ['orphaned-ref', 'some-secret-value-here-long-enough'],
    ], PASSPHRASE);

    const output = runList(dir, configPath, vaultPath, 'wrong-passphrase!!');

    assert.ok(output.includes('vault locked') || output.includes('Could not unlock'), 'should indicate vault locked');
    assert.ok(
      !output.includes('Additional secrets in store'),
      'should NOT show orphaned section when vault locked'
    );
  });
});
