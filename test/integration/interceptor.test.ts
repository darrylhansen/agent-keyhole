import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { VaultStore } from '../../src/store/vault.js';
import { spawnSidecar, type SidecarHandle } from '../../src/client/spawn.js';
import { IPCClient } from '../../src/client/ipc-client.js';
import { Interceptor } from '../../src/client/interceptor.js';
import { createMockServer, type MockServer } from '../helpers/mock-server.js';
import {
  TEST_SECRET,
  REDACTION_MARKER,
  makeConfig,
} from '../helpers/fixtures.js';
import type { AuthConfig, DomainWithPrefix } from '../../src/config/schema.js';

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-intercept-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Integration tests for the HTTP interceptor.
 * Tests are serial since they modify globals (http.request, fetch).
 */
describe('interceptor integration', () => {
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

  async function setupSidecar(
    server: MockServer,
    services: Record<string, any>,
    vaultSecrets: [string, string][],
  ): Promise<{ ipc: IPCClient; config: ReturnType<typeof makeConfig> }> {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const vault = new VaultStore(vaultPath);
    await vault.create('pass');
    await vault.setMany(vaultSecrets, 'pass');

    const config = makeConfig(services);
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

    return { ipc, config };
  }

  it('fetch() managed domain → intercepted with auth + masking', async () => {
    const server = await createMockServer([
      {
        method: 'GET',
        path: '/user',
        body: JSON.stringify({ login: 'octocat', token: TEST_SECRET }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(server);

    const { ipc, config } = await setupSidecar(
      server,
      {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: server.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    interceptor = new Interceptor(ipc, config);
    interceptor.install();

    try {
      const response = await fetch(`${server.url}/user`);
      assert.equal(response.status, 200);

      const body = await response.json();
      assert.equal(body.login, 'octocat');
      assert.equal(body.token, REDACTION_MARKER);

      // Verify upstream received real auth
      const upstream = server.getRequests('/user');
      assert.ok(upstream.length > 0);
      assert.equal(upstream[0].headers['authorization'], `Bearer ${TEST_SECRET}`);
    } finally {
      interceptor.uninstall();
      interceptor = null;
    }
  });

  it('fetch() unmanaged domain → passes through', async () => {
    // Start an "unmanaged" server
    const unmanagedServer = await createMockServer([
      {
        method: 'GET',
        path: '/public',
        body: JSON.stringify({ data: 'public' }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(unmanagedServer);

    // Managed server
    const managedServer = await createMockServer([
      { method: 'GET', path: '/', body: '{}' },
    ]);
    servers.push(managedServer);

    const { ipc, config } = await setupSidecar(
      managedServer,
      {
        github: {
          // Only manages a domain that doesn't match the unmanaged server
          domains: ['api.github.com'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: managedServer.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    interceptor = new Interceptor(ipc, config);
    interceptor.install();

    try {
      // This request to 127.0.0.1 should pass through since the config
      // only manages api.github.com
      const response = await fetch(`${unmanagedServer.url}/public`);
      assert.equal(response.status, 200);

      const body = await response.json();
      assert.equal(body.data, 'public');

      // Verify no auth was injected
      const reqs = unmanagedServer.getRequests('/public');
      assert.ok(reqs.length > 0);
      assert.ok(!reqs[0].headers['authorization']);
    } finally {
      interceptor.uninstall();
      interceptor = null;
    }
  });

  it('http.request() managed domain → intercepted', async () => {
    const server = await createMockServer([
      {
        method: 'GET',
        path: '/repos',
        body: JSON.stringify({ repos: ['a', 'b'] }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(server);

    const { ipc, config } = await setupSidecar(
      server,
      {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: server.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    interceptor = new Interceptor(ipc, config);
    interceptor.install();

    try {
      const body = await new Promise<string>((resolve, reject) => {
        const req = http.request(`${server.url}/repos`, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => resolve(Buffer.concat(chunks).toString()));
        });
        req.on('error', reject);
        req.end();
      });

      const parsed = JSON.parse(body);
      assert.deepEqual(parsed.repos, ['a', 'b']);

      // Upstream should have received auth
      const reqs = server.getRequests('/repos');
      assert.ok(reqs.length > 0);
      assert.equal(reqs[0].headers['authorization'], `Bearer ${TEST_SECRET}`);
    } finally {
      interceptor.uninstall();
      interceptor = null;
    }
  });

  it('uninstall() restores originals', async () => {
    const server = await createMockServer([
      { method: 'GET', path: '/', body: '{}' },
    ]);
    servers.push(server);

    const { ipc, config } = await setupSidecar(
      server,
      {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: server.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    const origFetch = globalThis.fetch;
    const origHttpReq = http.request;

    interceptor = new Interceptor(ipc, config);
    interceptor.install();

    assert.notEqual(globalThis.fetch, origFetch);
    assert.notEqual(http.request, origHttpReq);

    interceptor.uninstall();
    interceptor = null;

    assert.equal(globalThis.fetch, origFetch);
    assert.equal(http.request, origHttpReq);
  });

  it('path-prefix routing: two services on same domain', async () => {
    const server = await createMockServer([
      {
        method: 'GET',
        path: '/v1/resource',
        body: JSON.stringify({ service: 'v1' }),
        headers: { 'Content-Type': 'application/json' },
      },
      {
        method: 'GET',
        path: '/v2/resource',
        body: JSON.stringify({ service: 'v2' }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(server);

    const { ipc, config } = await setupSidecar(
      server,
      {
        'svc-a': {
          domains: [{ host: '127.0.0.1', path_prefix: '/v1' } as DomainWithPrefix],
          auth: { type: 'bearer', secret_ref: 'token-a' } as AuthConfig,
          base_url: server.url,
        },
        'svc-b': {
          domains: [{ host: '127.0.0.1', path_prefix: '/v2' } as DomainWithPrefix],
          auth: { type: 'bearer', secret_ref: 'token-b' } as AuthConfig,
          base_url: server.url,
        },
      },
      [
        ['token-a', 'secret-aaa-long-enough-for-registry'],
        ['token-b', 'secret-bbb-long-enough-for-registry'],
      ],
    );

    interceptor = new Interceptor(ipc, config);
    interceptor.install();

    try {
      const r1 = await fetch(`${server.url}/v1/resource`);
      assert.equal(r1.status, 200);

      const r2 = await fetch(`${server.url}/v2/resource`);
      assert.equal(r2.status, 200);

      const v1Reqs = server.getRequests('/v1/resource');
      const v2Reqs = server.getRequests('/v2/resource');
      assert.ok(v1Reqs.length > 0);
      assert.ok(v2Reqs.length > 0);

      // Different tokens for different services
      assert.equal(
        v1Reqs[0].headers['authorization'],
        'Bearer secret-aaa-long-enough-for-registry'
      );
      assert.equal(
        v2Reqs[0].headers['authorization'],
        'Bearer secret-bbb-long-enough-for-registry'
      );
    } finally {
      interceptor.uninstall();
      interceptor = null;
    }
  });
});
