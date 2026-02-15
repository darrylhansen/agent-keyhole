import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { VaultStore } from '../../src/store/vault.js';
import { spawnSidecar, type SidecarHandle } from '../../src/client/spawn.js';
import { IPCClient } from '../../src/client/ipc-client.js';
import { Interceptor } from '../../src/client/interceptor.js';
import { generateSafeEnv } from '../../src/client/safe-env.js';
import { createMockServer, type MockServer } from '../helpers/mock-server.js';
import { TEST_SECRET, OPENAI_SECRET, makeConfig } from '../helpers/fixtures.js';
import type { AuthConfig } from '../../src/config/schema.js';

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-firewall-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Credential firewall integration test.
 * This is the core threat model validation: a compromised agent that dumps
 * its entire environment must find nothing useful.
 */
describe('credential-firewall integration', () => {
  const handles: SidecarHandle[] = [];
  const clients: IPCClient[] = [];
  const servers: MockServer[] = [];
  const dirs: string[] = [];
  let interceptor: Interceptor | null = null;

  after(async () => {
    if (interceptor) interceptor.uninstall();
    for (const c of clients) try { await c.disconnect(); } catch {}
    for (const h of handles) try { h.child.kill('SIGKILL'); } catch {}
    for (const s of servers) try { await s.close(); } catch {}
    for (const d of dirs) try { fs.rmSync(d, { recursive: true, force: true }); } catch {}
  });

  it('safe env has placeholders, not real secrets', () => {
    const config = makeConfig({
      github: {
        domains: ['api.github.com'],
        auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
        base_url: 'https://api.github.com',
        sdk_env: { GITHUB_TOKEN: '{{placeholder}}' },
      },
      openai: {
        domains: ['api.openai.com'],
        auth: { type: 'bearer', secret_ref: 'openai-key' } as AuthConfig,
        base_url: 'https://api.openai.com',
        sdk_env: { OPENAI_API_KEY: '{{placeholder}}' },
        placeholder: 'CUSTOM_PLACEHOLDER',
      },
    });

    const env = generateSafeEnv(config);

    // Env vars should have placeholders, NOT real secrets
    assert.equal(env.GITHUB_TOKEN, 'KEYHOLE_MANAGED');
    assert.equal(env.OPENAI_API_KEY, 'CUSTOM_PLACEHOLDER');
    assert.ok(!Object.values(env).includes(TEST_SECRET));
    assert.ok(!Object.values(env).includes(OPENAI_SECRET));
  });

  it('full env scan: no real secret in any value', () => {
    const config = makeConfig({
      github: {
        domains: ['api.github.com'],
        auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
        base_url: 'https://api.github.com',
        sdk_env: { GITHUB_TOKEN: '{{placeholder}}' },
      },
    });

    const safeEnv = generateSafeEnv(config);
    const allSecrets = [TEST_SECRET, OPENAI_SECRET];

    for (const [key, value] of Object.entries(safeEnv)) {
      for (const secret of allSecrets) {
        assert.ok(
          !value.includes(secret),
          `Safe env var "${key}" contains a real secret`
        );
      }
    }
  });

  it('intercepted request authenticates with real secret (200)', async () => {
    // Mock server that validates auth header — returns 200 only if correct
    const server = await createMockServer([
      {
        method: 'GET',
        path: '/protected',
        handler: (req, res) => {
          const auth = req.headers['authorization'];
          if (auth === `Bearer ${TEST_SECRET}`) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ authenticated: true }));
          } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized', got: auth }));
          }
        },
      },
    ]);
    servers.push(server);

    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create('pass');
    await vault.setMany([['github-token', TEST_SECRET]], 'pass');

    const config = makeConfig({
      github: {
        domains: ['127.0.0.1'],
        auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
        base_url: server.url,
        sdk_env: { GITHUB_TOKEN: '{{placeholder}}' },
      },
    });
    config.vaultPath = vaultPath;

    const handle = await spawnSidecar(config, {
      store: 'vault',
      vaultPassphrase: 'pass',
      timeout: 10000,
    });
    handles.push(handle);

    const ipc = new IPCClient(handle.socketPath, handle.ott, { timeout: 5000 });
    clients.push(ipc);
    await ipc.connect();

    // Install interceptor
    interceptor = new Interceptor(ipc, config);
    interceptor.install();

    try {
      // Verify safe env doesn't have real secret
      const safeEnv = generateSafeEnv(config);
      assert.equal(safeEnv.GITHUB_TOKEN, 'KEYHOLE_MANAGED');
      assert.ok(!Object.values(safeEnv).includes(TEST_SECRET));

      // Make fetch call — sidecar should inject real secret
      const response = await fetch(`${server.url}/protected`);
      assert.equal(response.status, 200);

      const body = await response.json();
      assert.equal(body.authenticated, true);
    } finally {
      interceptor.uninstall();
      interceptor = null;
    }
  });
});
