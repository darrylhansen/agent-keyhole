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
import {
  TEST_SECRET,
  OPENAI_SECRET,
  REDACTION_MARKER,
  makeConfig,
} from '../helpers/fixtures.js';
import type { AuthConfig } from '../../src/config/schema.js';

/**
 * Integration roundtrip: real sidecar + real IPC client + mock upstream HTTP server.
 * Validates the full pipeline: IPC → request-builder → upstream fetch → response-masker → IPC.
 */

function tmpDir(): string {
  const id = crypto.randomBytes(8).toString('hex');
  const dir = path.join(os.tmpdir(), `keyhole-roundtrip-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describe('roundtrip integration', () => {
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

  async function setup(options: {
    routes: Parameters<typeof createMockServer>[0];
    services?: Record<string, any>;
    vaultSecrets?: [string, string][];
    passphrase?: string;
  }): Promise<{ ipc: IPCClient; server: MockServer; handle: SidecarHandle }> {
    const dir = tmpDir();
    dirs.push(dir);
    const vaultPath = path.join(dir, '.keyhole.vault');
    const passphrase = options.passphrase || 'test-pass';

    // 1. Create vault with secrets
    const vault = new VaultStore(vaultPath);
    await vault.create(passphrase);
    const secrets = options.vaultSecrets || [
      ['github-token', TEST_SECRET],
      ['openai-key', OPENAI_SECRET],
    ];
    await vault.setMany(secrets, passphrase);

    // 2. Start mock upstream
    const server = await createMockServer(options.routes);
    servers.push(server);

    // 3. Build config pointing to mock server
    const services = options.services || {
      github: {
        domains: ['127.0.0.1'],
        auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
        base_url: server.url,
      },
    };
    const config = makeConfig(services);
    config.vaultPath = vaultPath;

    // 4. Spawn sidecar
    const handle = await spawnSidecar(config, {
      store: 'vault',
      vaultPassphrase: passphrase,
      timeout: 10000,
    });
    handles.push(handle);
    assert.equal(handle.state, 'ready');

    // 5. Connect IPC client
    const ipc = new IPCClient(handle.socketPath, handle.ott, { timeout: 5000 });
    clients.push(ipc);
    await ipc.connect();

    return { ipc, server, handle };
  }

  it('full pipeline: IPC → upstream → masked response', async () => {
    const { ipc, server } = await setup({
      routes: [
        {
          method: 'GET',
          path: '/user',
          body: JSON.stringify({
            login: 'octocat',
            token: TEST_SECRET,
          }),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer should-be-scrubbed`,
          },
        },
      ],
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/user',
      headers: {},
      bodyEncoding: 'utf8',
    });

    // Status forwarded
    assert.equal(response.status, 200);

    // L1: Authorization header scrubbed from response
    assert.ok(!response.headers['authorization']);

    // L2: Known secret replaced in JSON body
    const body = JSON.parse(response.body);
    assert.equal(body.login, 'octocat');
    assert.equal(body.token, REDACTION_MARKER);

    // Redacted flag set
    assert.equal(response.redacted, true);

    // Verify upstream received auth
    const upstream = server.getRequests('/user');
    assert.equal(upstream.length, 1);
    assert.equal(
      upstream[0].headers['authorization'],
      `Bearer ${TEST_SECRET}`
    );
  });

  it('upstream 500 forwarded with masked body', async () => {
    const { ipc } = await setup({
      routes: [
        {
          method: 'GET',
          path: '/error',
          status: 500,
          body: JSON.stringify({
            error: 'Internal error',
            debug_token: TEST_SECRET,
          }),
          headers: { 'Content-Type': 'application/json' },
        },
      ],
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/error',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 500);
    const body = JSON.parse(response.body);
    assert.equal(body.error, 'Internal error');
    assert.equal(body.debug_token, REDACTION_MARKER);
  });

  it('binary request roundtrip', async () => {
    const pngHeader = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ]);
    const imageData = Buffer.concat([pngHeader, crypto.randomBytes(64)]);

    const { ipc, server } = await setup({
      routes: [
        {
          method: 'POST',
          path: '/upload',
          body: JSON.stringify({ ok: true }),
          headers: { 'Content-Type': 'application/json' },
        },
      ],
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'POST',
      path: '/upload',
      headers: { 'content-type': 'image/png' },
      bodyBase64: imageData.toString('base64'),
      bodyEncoding: 'base64',
    });

    assert.equal(response.status, 200);

    // Verify the upstream received the binary body
    const upstream = server.getRequests('/upload');
    assert.equal(upstream.length, 1);
    assert.ok(upstream[0].rawBody.equals(imageData));
  });

  it('binary response roundtrip', async () => {
    const imageData = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      crypto.randomBytes(64),
    ]);

    const { ipc } = await setup({
      routes: [
        {
          method: 'GET',
          path: '/image.png',
          body: imageData,
          headers: { 'Content-Type': 'image/png' },
        },
      ],
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/image.png',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);
    assert.equal(response.bodyEncoding, 'base64');
    assert.ok(response.bodyBase64);

    const decoded = Buffer.from(response.bodyBase64!, 'base64');
    assert.ok(decoded.equals(imageData));
  });

  it('upstream connection refused → 502', async () => {
    // Point sidecar at a port that nothing is listening on
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
        base_url: 'http://127.0.0.1:1', // Port 1 — nothing listens there
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

    // IPC client rejects when response has an error field
    await assert.rejects(
      ipc.send({
        id: crypto.randomUUID(),
        service: 'github',
        method: 'GET',
        path: '/test',
        headers: {},
        bodyEncoding: 'utf8',
      }),
      /Upstream request failed/
    );
  });

  it('health endpoint returns ready state', async () => {
    const { ipc } = await setup({
      routes: [{ method: 'GET', path: '/', body: '{}' }],
    });

    const response = await ipc.send({
      id: crypto.randomUUID(),
      service: '__health__',
      method: 'GET',
      path: '/',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);
    const body = JSON.parse(response.body);
    assert.equal(body.state, 'ready');
    assert.ok(typeof body.uptime === 'number');
  });
});
