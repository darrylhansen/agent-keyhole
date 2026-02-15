import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import {
  startIPCServer,
  stopIPCServer,
  updateServerHandlers,
} from '../../src/sidecar/ipc-server.js';
import { AuditLogger } from '../../src/sidecar/audit-logger.js';
import type { KeyholeRequest, KeyholeResponse } from '../../src/sidecar/ipc-types.js';

const OTT = crypto.randomBytes(32).toString('hex');

function makeLogger(): AuditLogger {
  // Suppress log output in tests
  return new AuditLogger({ level: 'error', output: 'stderr' });
}

function sendRequest(conn: net.Socket, request: KeyholeRequest): void {
  const payload = Buffer.from(JSON.stringify(request), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  conn.write(Buffer.concat([header, payload]));
}

function readResponse(conn: net.Socket): Promise<KeyholeResponse> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timeout = setTimeout(() => reject(new Error('Read timeout')), 5000);

    const onData = (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);
      if (buffer.length >= 4) {
        const payloadLength = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + payloadLength) {
          clearTimeout(timeout);
          conn.removeListener('data', onData);
          const payload = buffer.subarray(4, 4 + payloadLength);
          resolve(JSON.parse(payload.toString('utf-8')));
        }
      }
    };

    conn.on('data', onData);
    conn.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

function connectToSocket(socketPath: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(socketPath, () => resolve(conn));
    conn.on('error', reject);
  });
}

// NOTE: Tests in this describe block share a single IPC server instance started
// in the first test. They must run in declaration order and are NOT independently
// runnable. The server starts in PENDING_UNLOCK state (builder=null) and is
// torn down in after().
describe('ipc-server', () => {
  let socketPath: string;

  after(async () => {
    await stopIPCServer(socketPath);
  });

  it('starts and accepts connections', async () => {
    const tmpDir = path.join(os.tmpdir(), `kh-test-${crypto.randomBytes(8).toString('hex')}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    socketPath = await startIPCServer(OTT, null, null, makeLogger(), tmpDir);
    assert.ok(socketPath.endsWith('.sock'));
    assert.ok(fs.existsSync(socketPath));

    const conn = await connectToSocket(socketPath);
    conn.destroy();
  });

  it('health endpoint — pending_unlock returns 503', async () => {
    // Server was started with builder=null → pending_unlock state
    const conn = await connectToSocket(socketPath);
    const reqId = crypto.randomUUID();

    sendRequest(conn, {
      id: reqId,
      ott: OTT,
      service: '__health__',
      method: 'GET',
      path: '/',
      headers: {},
      bodyEncoding: 'utf8',
    });

    const res = await readResponse(conn);
    assert.equal(res.id, reqId);
    assert.equal(res.status, 503);
    const body = JSON.parse(res.body);
    assert.equal(body.state, 'pending_unlock');
    conn.destroy();
  });

  it('PENDING_UNLOCK — non-health request rejected with 503', async () => {
    const conn = await connectToSocket(socketPath);
    const reqId = crypto.randomUUID();

    sendRequest(conn, {
      id: reqId,
      ott: OTT,
      service: 'github',
      method: 'GET',
      path: '/user',
      headers: {},
      bodyEncoding: 'utf8',
    });

    const res = await readResponse(conn);
    assert.equal(res.status, 503);
    assert.ok(res.error?.includes('Vault is locked'));
    conn.destroy();
  });

  it('timing-safe OTT validation — invalid OTT rejected with 403', async () => {
    const conn = await connectToSocket(socketPath);
    const reqId = crypto.randomUUID();
    const wrongOtt = crypto.randomBytes(32).toString('hex');

    sendRequest(conn, {
      id: reqId,
      ott: wrongOtt,
      service: 'github',
      method: 'GET',
      path: '/user',
      headers: {},
      bodyEncoding: 'utf8',
    });

    const res = await readResponse(conn);
    assert.equal(res.status, 403);
    assert.ok(res.error?.includes('Invalid authentication token'));
    conn.destroy();
  });

  it('timing-safe OTT validation — different length OTT rejected', async () => {
    const conn = await connectToSocket(socketPath);
    const reqId = crypto.randomUUID();

    sendRequest(conn, {
      id: reqId,
      ott: 'short-ott',
      service: 'github',
      method: 'GET',
      path: '/user',
      headers: {},
      bodyEncoding: 'utf8',
    });

    const res = await readResponse(conn);
    assert.equal(res.status, 403);
    assert.ok(res.error?.includes('Invalid authentication token'));
    conn.destroy();
  });

  it('malformed JSON — connection stays alive', async () => {
    const conn = await connectToSocket(socketPath);

    // Send garbled payload
    const garbled = Buffer.from('not{valid json!!!', 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(garbled.length, 0);
    conn.write(Buffer.concat([header, garbled]));

    // Wait a bit, then send a valid request — should still work
    await new Promise((r) => setTimeout(r, 50));

    const reqId = crypto.randomUUID();
    sendRequest(conn, {
      id: reqId,
      ott: OTT,
      service: '__health__',
      method: 'GET',
      path: '/',
      headers: {},
      bodyEncoding: 'utf8',
    });

    const res = await readResponse(conn);
    assert.equal(res.id, reqId);
    assert.equal(res.status, 503); // pending_unlock
    conn.destroy();
  });

  it('MAX_IPC_MESSAGE_SIZE enforcement — oversized message destroys connection', async () => {
    const conn = await connectToSocket(socketPath);

    // Send a header claiming a payload larger than MAX_IPC_MESSAGE_SIZE (10MB + 64KB)
    const oversizeHeader = Buffer.alloc(4);
    oversizeHeader.writeUInt32BE(11 * 1024 * 1024, 0); // 11MB > limit
    conn.write(oversizeHeader);

    // Connection should be destroyed by server
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Expected connection close')), 3000);
      conn.on('close', () => { clearTimeout(timeout); resolve(); });
      conn.on('error', () => { clearTimeout(timeout); resolve(); });
    });
  });
});
