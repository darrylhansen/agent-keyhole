import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { VaultStore } from '../../src/store/vault.js';
import { spawnSidecar, type SidecarHandle } from '../../src/client/spawn.js';
import { IPCClient } from '../../src/client/ipc-client.js';
import { createMockServer, type MockServer } from '../helpers/mock-server.js';
import { TEST_SECRET, OPENAI_SECRET, makeConfig } from '../helpers/fixtures.js';
import type { AuthConfig } from '../../src/config/schema.js';

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-agent-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Integration tests for multi-agent access control.
 * Tests OTT validation and per-agent service authorization.
 */
describe('multi-agent integration', () => {
  const handles: SidecarHandle[] = [];
  const clients: IPCClient[] = [];
  const servers: MockServer[] = [];
  const dirs: string[] = [];

  after(async () => {
    for (const c of clients) try { await c.disconnect(); } catch {}
    for (const h of handles) try { h.child.kill('SIGKILL'); } catch {}
    for (const s of servers) try { await s.close(); } catch {}
    for (const d of dirs) try { fs.rmSync(d, { recursive: true, force: true }); } catch {}
  });

  async function setupAgent(options: {
    services: Record<string, any>;
    agents?: Record<string, { services: string[] }>;
    vaultSecrets: [string, string][];
    agentName?: string;
  }): Promise<{ ipc: IPCClient; handle: SidecarHandle }> {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create('pass');
    await vault.setMany(options.vaultSecrets, 'pass');

    const server = await createMockServer([
      {
        method: 'GET',
        path: '/test',
        body: JSON.stringify({ ok: true }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(server);

    const config = makeConfig(options.services, options.agents);
    config.vaultPath = vaultPath;
    // Point base_urls to mock server
    for (const svc of Object.values(config.services)) {
      svc.base_url = server.url;
    }

    const handle = await spawnSidecar(config, {
      store: 'vault',
      vaultPassphrase: 'pass',
      agent: options.agentName,
      timeout: 10000,
    });
    handles.push(handle);

    const ipc = new IPCClient(handle.socketPath, handle.ott, {
      timeout: 5000,
      agent: options.agentName,
    });
    clients.push(ipc);
    await ipc.connect();

    return { ipc, handle };
  }

  it('authorized agent succeeds', async () => {
    const { ipc } = await setupAgent({
      services: {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: '',
        },
        openai: {
          domains: ['api.openai.com'],
          auth: { type: 'bearer', secret_ref: 'openai-key' } as AuthConfig,
          base_url: '',
        },
      },
      agents: {
        'content-bot': { services: ['github'] },
        'coding-bot': { services: ['github', 'openai'] },
      },
      vaultSecrets: [
        ['github-token', TEST_SECRET],
        ['openai-key', OPENAI_SECRET],
      ],
      agentName: 'content-bot',
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/test',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);
  });

  it('unauthorized agent → 403', async () => {
    const { ipc } = await setupAgent({
      services: {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: '',
        },
        openai: {
          domains: ['api.openai.com'],
          auth: { type: 'bearer', secret_ref: 'openai-key' } as AuthConfig,
          base_url: '',
        },
      },
      agents: {
        'content-bot': { services: ['github'] },
      },
      vaultSecrets: [
        ['github-token', TEST_SECRET],
        ['openai-key', OPENAI_SECRET],
      ],
      agentName: 'content-bot',
    });

    // content-bot only has access to github, not openai
    await assert.rejects(
      ipc.send({
        id: crypto.randomUUID(),
        service: 'openai',
        method: 'GET',
        path: '/test',
        headers: {},
        bodyEncoding: 'utf8',
      }),
      /not authorized for service/
    );
  });

  it('no agents config = all services allowed', async () => {
    const { ipc } = await setupAgent({
      services: {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: '',
        },
      },
      // No agents config
      vaultSecrets: [['github-token', TEST_SECRET]],
      agentName: 'any-bot',
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/test',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);
  });

  it('invalid OTT → 403', async () => {
    const { handle } = await setupAgent({
      services: {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: '',
        },
      },
      vaultSecrets: [['github-token', TEST_SECRET]],
    });

    // Connect with WRONG OTT
    const badIpc = new IPCClient(handle.socketPath, 'bad-ott'.repeat(8), {
      timeout: 5000,
    });
    clients.push(badIpc);
    await badIpc.connect();

    await assert.rejects(
      badIpc.send({
        id: crypto.randomUUID(),
        service: 'github',
        method: 'GET',
        path: '/test',
        headers: {},
        bodyEncoding: 'utf8',
      }),
      /Invalid authentication token/
    );
  });
});
