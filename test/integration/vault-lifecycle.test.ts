import { describe, it, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { VaultStore } from '../../src/store/vault.js';

/**
 * Integration tests for VaultStore lifecycle: create, unlock, get, set, setMany.
 * Each test uses an isolated temp directory to prevent collisions.
 */

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-vault-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describe('VaultStore lifecycle', () => {
  const dirs: string[] = [];

  after(() => {
    for (const d of dirs) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch {}
    }
  });

  it('create → file exists with 0600 permissions', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('test-pass');

    assert.ok(fs.existsSync(vaultPath));
    const stat = fs.statSync(vaultPath);
    // 0o600 = owner read+write, no group/other
    const mode = stat.mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it('unlock correct passphrase → secrets accessible', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('test-pass');
    await vault.set('my-secret', 'secret-value', 'test-pass');

    // Create fresh instance to simulate cold open
    const vault2 = new VaultStore(vaultPath);
    assert.equal(vault2.isLocked, true);

    await vault2.unlock('test-pass');
    assert.equal(vault2.isLocked, false);

    const value = await vault2.get('my-secret');
    assert.equal(value, 'secret-value');
  });

  it('wrong passphrase → error, remains locked', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('correct-pass');

    const vault2 = new VaultStore(vaultPath);
    await assert.rejects(
      vault2.unlock('wrong-pass'),
      /Invalid passphrase or corrupted vault/
    );
    assert.equal(vault2.isLocked, true);
  });

  it('create fails if vault already exists', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass1');
    await assert.rejects(
      vault.create('pass2'),
      /Vault already exists/
    );
  });

  it('get on locked vault throws', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');

    const vault2 = new VaultStore(vaultPath);
    await assert.rejects(
      vault2.get('anything'),
      /Vault is locked/
    );
  });

  it('get non-existent secret throws', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.unlock('pass');
    await assert.rejects(
      vault.get('nonexistent'),
      /Secret not found in vault/
    );
  });

  it('setMany batches secrets in exactly one disk write', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.unlock('pass');

    // Count writeFileSync calls during setMany
    let writeCount = 0;
    const origWrite = fs.writeFileSync;
    const writeMock = mock.fn((...args: any[]) => {
      // Only count writes to the vault temp path
      if (typeof args[0] === 'string' && args[0].includes('keyhole.vault')) {
        writeCount++;
      }
      return (origWrite as any).apply(fs, args);
    });
    (fs as any).writeFileSync = writeMock;

    try {
      await vault.setMany(
        [
          ['secret-a', 'value-a'],
          ['secret-b', 'value-b'],
          ['secret-c', 'value-c'],
        ],
        'pass'
      );

      // setMany writes to .tmp then rename — exactly 1 writeFileSync call
      assert.equal(writeCount, 1);
    } finally {
      (fs as any).writeFileSync = origWrite;
    }

    // Verify all secrets readable
    const a = await vault.get('secret-a');
    const b = await vault.get('secret-b');
    const c = await vault.get('secret-c');
    assert.equal(a, 'value-a');
    assert.equal(b, 'value-b');
    assert.equal(c, 'value-c');
  });

  it('list returns all secret refs', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.setMany(
      [
        ['github-token', 'ghp_abc'],
        ['openai-key', 'sk-xyz'],
      ],
      'pass'
    );

    const vault2 = new VaultStore(vaultPath);
    await vault2.unlock('pass');
    const refs = await vault2.list();
    assert.deepEqual(refs.sort(), ['github-token', 'openai-key']);
  });

  it('has returns true/false correctly', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.set('exists', 'val', 'pass');

    assert.equal(await vault.has('exists'), true);
    assert.equal(await vault.has('nope'), false);
  });

  it('delete removes a secret', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.set('to-delete', 'val', 'pass');
    assert.equal(await vault.has('to-delete'), true);

    await vault.delete('to-delete', 'pass');
    assert.equal(await vault.has('to-delete'), false);
  });

  it('atomic write: vault not corrupted on normal save', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.setMany(
      [
        ['s1', 'v1'],
        ['s2', 'v2'],
      ],
      'pass'
    );

    // .tmp file should not exist after successful save
    assert.ok(!fs.existsSync(vaultPath + '.tmp'));

    // Re-open and verify
    const vault2 = new VaultStore(vaultPath);
    await vault2.unlock('pass');
    assert.equal(await vault2.get('s1'), 'v1');
    assert.equal(await vault2.get('s2'), 'v2');
  });

  it('passphrase required for set/delete', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);

    await vault.create('pass');
    await vault.unlock('pass');

    await assert.rejects(
      vault.set('key', 'val'),
      /Passphrase required/
    );
    await assert.rejects(
      vault.delete('key'),
      /Passphrase required/
    );
  });

  it('vault file not found throws on unlock', async () => {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, 'nonexistent.vault');
    const vault = new VaultStore(vaultPath);

    await assert.rejects(
      vault.unlock('pass'),
      /Vault not found/
    );
  });
});
