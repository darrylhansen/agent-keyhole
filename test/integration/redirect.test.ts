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
import { TEST_SECRET, makeConfig } from '../helpers/fixtures.js';
import type { AuthConfig } from '../../src/config/schema.js';

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-redirect-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Integration tests for redirect auth stripping/re-injection.
 * The sidecar follows redirects manually, stripping auth for untrusted hosts
 * and re-injecting for trusted hosts.
 */
describe('redirect integration', () => {
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

  async function setupWithServers(
    trustedServer: MockServer,
    untrustedServer: MockServer | null,
    services: Record<string, any>,
    vaultSecrets: [string, string][],
  ): Promise<IPCClient> {
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

    return ipc;
  }

  it('untrusted redirect → auth stripped', async () => {
    // Untrusted server records whether auth was sent
    const untrusted = await createMockServer([
      {
        method: 'GET',
        path: '/final',
        body: JSON.stringify({ result: 'ok' }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(untrusted);

    // Redirect target uses "localhost" hostname — different from the trusted
    // domain "127.0.0.1". Both resolve to the same IP but the sidecar's
    // redirect handler does string comparison on hostnames.
    const untrustedViaLocalhost = `http://localhost:${untrusted.port}`;

    // Trusted server redirects to untrusted (via localhost hostname)
    const trusted = await createMockServer([
      {
        method: 'GET',
        path: '/redirect',
        redirectTo: `${untrustedViaLocalhost}/final`,
        redirectStatus: 302,
      },
    ]);
    servers.push(trusted);

    const ipc = await setupWithServers(
      trusted,
      untrusted,
      {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: trusted.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/redirect',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);

    // The untrusted server should NOT have received auth
    const finalReqs = untrusted.getRequests('/final');
    assert.ok(finalReqs.length > 0);
    assert.ok(
      !finalReqs[0].headers['authorization'],
      'Auth should be stripped on untrusted redirect'
    );
  });

  it('no Location header → response returned as-is', async () => {
    const server = await createMockServer([
      {
        method: 'GET',
        path: '/no-location',
        status: 301,
        body: 'Moved',
        headers: { 'Content-Type': 'text/plain' },
        // No redirectTo → no Location header
      },
    ]);
    servers.push(server);

    const ipc = await setupWithServers(
      server,
      null,
      {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: server.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/no-location',
      headers: {},
      bodyEncoding: 'utf8',
    });

    // 301 without Location → returned to client
    assert.equal(response.status, 301);
  });

  it('>10 redirects → error', async () => {
    // Create a server that always redirects to itself
    const server = await createMockServer([
      {
        method: 'GET',
        path: '/loop',
        redirectTo: '/loop', // Relative redirect to self
        redirectStatus: 302,
      },
    ]);
    servers.push(server);

    // We need the redirectTo to be absolute for fetch
    server.addRoute({
      method: 'GET',
      path: '/loop',
      handler: (req, res) => {
        const url = `http://127.0.0.1:${server.port}/loop`;
        res.writeHead(302, { Location: url });
        res.end();
      },
    });

    const ipc = await setupWithServers(
      server,
      null,
      {
        github: {
          domains: ['127.0.0.1'],
          auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
          base_url: server.url,
        },
      },
      [['github-token', TEST_SECRET]],
    );

    await assert.rejects(
      ipc.send({
        id: crypto.randomUUID(),
        service: 'github',
        method: 'GET',
        path: '/loop',
        headers: {},
        bodyEncoding: 'utf8',
      }),
      /Too many redirects/
    );
  });

  it('query_param: strip on untrusted redirect', async () => {
    const untrusted = await createMockServer([
      {
        method: 'GET',
        path: '/final',
        body: JSON.stringify({ ok: true }),
        headers: { 'Content-Type': 'application/json' },
      },
    ]);
    servers.push(untrusted);

    // Use "localhost" for redirect target — different hostname from trusted "127.0.0.1"
    const untrustedViaLocalhost = `http://localhost:${untrusted.port}`;

    const trusted = await createMockServer([
      {
        method: 'GET',
        path: '/redirect',
        redirectTo: `${untrustedViaLocalhost}/final`,
        redirectStatus: 302,
      },
    ]);
    servers.push(trusted);

    const ipc = await setupWithServers(
      trusted,
      untrusted,
      {
        maps: {
          domains: ['127.0.0.1'],
          auth: {
            type: 'query_param',
            param_name: 'key',
            secret_ref: 'maps-key',
          } as AuthConfig,
          base_url: trusted.url,
        },
      },
      [['maps-key', TEST_SECRET]],
    );

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'maps',
      method: 'GET',
      path: '/redirect',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);

    // The untrusted redirect URL should NOT contain the key param
    const finalReqs = untrusted.getRequests('/final');
    assert.ok(finalReqs.length > 0);
    assert.ok(
      !finalReqs[0].path.includes(TEST_SECRET),
      'Query param secret should be stripped on untrusted redirect'
    );
  });
});
