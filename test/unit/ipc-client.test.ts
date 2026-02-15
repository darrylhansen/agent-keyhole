import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { IPCClient } from '../../src/client/ipc-client.js';
import type { KeyholeResponse } from '../../src/sidecar/ipc-types.js';

/**
 * Helper: spin up a real net.Server on a temp Unix socket.
 * The server reads length-prefixed frames and optionally writes back responses.
 */
function createTestServer(
  socketPath: string,
  handler?: (request: any, conn: net.Socket) => void
): net.Server {
  const server = net.createServer((conn) => {
    let buffer = Buffer.alloc(0);

    conn.on('data', (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);

      while (buffer.length >= 4) {
        const payloadLength = buffer.readUInt32BE(0);
        if (buffer.length < 4 + payloadLength) break;

        const payload = buffer.subarray(4, 4 + payloadLength);
        buffer = buffer.subarray(4 + payloadLength);

        const request = JSON.parse(payload.toString('utf-8'));
        if (handler) handler(request, conn);
      }
    });
  });

  return server;
}

function sendResponse(conn: net.Socket, response: KeyholeResponse): void {
  const payload = Buffer.from(JSON.stringify(response), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  conn.write(Buffer.concat([header, payload]));
}

function tmpSocket(): string {
  return path.join(os.tmpdir(), `keyhole-test-${crypto.randomBytes(8).toString('hex')}.sock`);
}

describe('IPCClient', () => {
  const cleanups: Array<() => void> = [];

  after(() => {
    for (const fn of cleanups) {
      try { fn(); } catch {}
    }
  });

  it('length-prefix framing encode/decode round-trip', async () => {
    const socketPath = tmpSocket();
    const server = createTestServer(socketPath, (req, conn) => {
      sendResponse(conn, {
        id: req.id,
        status: 200,
        headers: {},
        body: JSON.stringify({ echo: req.service }),
        bodyEncoding: 'utf8',
      });
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    cleanups.push(() => { server.close(); try { fs.unlinkSync(socketPath); } catch {} });

    const client = new IPCClient(socketPath, 'test-ott', { timeout: 5000 });
    await client.connect();

    const response = await client.send({
      id: crypto.randomUUID(),
      service: 'github',
      method: 'GET',
      path: '/user',
      headers: {},
      bodyEncoding: 'utf8',
    });

    assert.equal(response.status, 200);
    assert.equal(JSON.parse(response.body).echo, 'github');
    await client.disconnect();
  });

  it('concurrent requests matched by ID', async () => {
    const socketPath = tmpSocket();
    const server = createTestServer(socketPath, (req, conn) => {
      // Respond in reverse order to test ID correlation
      const delay = req.path === '/first' ? 50 : req.path === '/second' ? 30 : 10;
      setTimeout(() => {
        sendResponse(conn, {
          id: req.id,
          status: 200,
          headers: {},
          body: req.path,
          bodyEncoding: 'utf8',
        });
      }, delay);
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    cleanups.push(() => { server.close(); try { fs.unlinkSync(socketPath); } catch {} });

    const client = new IPCClient(socketPath, 'test-ott', { timeout: 5000 });
    await client.connect();

    const [r1, r2, r3] = await Promise.all([
      client.send({ id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/first', headers: {}, bodyEncoding: 'utf8' }),
      client.send({ id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/second', headers: {}, bodyEncoding: 'utf8' }),
      client.send({ id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/third', headers: {}, bodyEncoding: 'utf8' }),
    ]);

    assert.equal(r1.body, '/first');
    assert.equal(r2.body, '/second');
    assert.equal(r3.body, '/third');
    await client.disconnect();
  });

  it('request timeout rejects after timeout period', async () => {
    const socketPath = tmpSocket();
    // Server never responds
    const server = createTestServer(socketPath);

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    cleanups.push(() => { server.close(); try { fs.unlinkSync(socketPath); } catch {} });

    const client = new IPCClient(socketPath, 'test-ott', { timeout: 100 });
    await client.connect();

    await assert.rejects(
      client.send({ id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/slow', headers: {}, bodyEncoding: 'utf8' }),
      /timed out/i
    );
    await client.disconnect();
  });

  it('updateConnection: reconnects to a new socket with new OTT', async () => {
    // First server
    const socketPath1 = tmpSocket();
    const server1 = createTestServer(socketPath1, (req, conn) => {
      sendResponse(conn, {
        id: req.id, status: 200, headers: {}, body: 'server1', bodyEncoding: 'utf8',
      });
    });
    await new Promise<void>((resolve) => server1.listen(socketPath1, resolve));
    cleanups.push(() => { server1.close(); try { fs.unlinkSync(socketPath1); } catch {} });

    const client = new IPCClient(socketPath1, 'ott1', { timeout: 5000 });
    await client.connect();

    const r1 = await client.send({
      id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/', headers: {}, bodyEncoding: 'utf8',
    });
    assert.equal(r1.body, 'server1');

    // Second server on a different socket
    const socketPath2 = tmpSocket();
    const server2 = createTestServer(socketPath2, (req, conn) => {
      sendResponse(conn, {
        id: req.id, status: 200, headers: {}, body: 'server2', bodyEncoding: 'utf8',
      });
    });
    await new Promise<void>((resolve) => server2.listen(socketPath2, resolve));
    cleanups.push(() => { server2.close(); try { fs.unlinkSync(socketPath2); } catch {} });

    // updateConnection: disconnects from server1, reconnects to server2
    await client.updateConnection(socketPath2, 'ott2');

    const r2 = await client.send({
      id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/', headers: {}, bodyEncoding: 'utf8',
    });
    assert.equal(r2.body, 'server2');

    await client.disconnect();
  });

  it('malformed JSON from server handled gracefully', async () => {
    const socketPath = tmpSocket();
    let callCount = 0;

    const server = net.createServer((conn) => {
      let buffer = Buffer.alloc(0);
      conn.on('data', (data: Buffer) => {
        buffer = Buffer.concat([buffer, data]);

        while (buffer.length >= 4) {
          const payloadLength = buffer.readUInt32BE(0);
          if (buffer.length < 4 + payloadLength) break;

          const payload = buffer.subarray(4, 4 + payloadLength);
          buffer = buffer.subarray(4 + payloadLength);
          const request = JSON.parse(payload.toString('utf-8'));
          callCount++;

          if (callCount === 1) {
            // First: send malformed JSON
            const garbled = Buffer.from('not{valid json', 'utf-8');
            const header = Buffer.alloc(4);
            header.writeUInt32BE(garbled.length, 0);
            conn.write(Buffer.concat([header, garbled]));

            // Then immediately send a real response
            sendResponse(conn, {
              id: request.id, status: 200, headers: {}, body: 'recovered', bodyEncoding: 'utf8',
            });
          } else {
            sendResponse(conn, {
              id: request.id, status: 200, headers: {}, body: 'ok', bodyEncoding: 'utf8',
            });
          }
        }
      });
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    cleanups.push(() => { server.close(); try { fs.unlinkSync(socketPath); } catch {} });

    const client = new IPCClient(socketPath, 'test-ott', { timeout: 5000 });
    await client.connect();

    // First message: server sends garbled + valid response
    const r1 = await client.send({
      id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/', headers: {}, bodyEncoding: 'utf8',
    });
    assert.equal(r1.body, 'recovered');

    await client.disconnect();
  });

  it('intentional disconnect — no reconnect attempt', async () => {
    const socketPath = tmpSocket();
    const server = createTestServer(socketPath, (req, conn) => {
      sendResponse(conn, {
        id: req.id, status: 200, headers: {}, body: 'ok', bodyEncoding: 'utf8',
      });
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    cleanups.push(() => { server.close(); try { fs.unlinkSync(socketPath); } catch {} });

    const client = new IPCClient(socketPath, 'test-ott', { timeout: 5000 });
    await client.connect();
    await client.disconnect();

    // After intentional disconnect, send should throw
    await assert.rejects(
      client.send({ id: crypto.randomUUID(), service: 'x', method: 'GET', path: '/', headers: {}, bodyEncoding: 'utf8' }),
      /Not connected/
    );
  });
});
