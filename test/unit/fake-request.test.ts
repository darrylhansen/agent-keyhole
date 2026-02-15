import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'stream';
import { FakeClientRequest } from '../../src/client/fake-request.js';
import { IPCClient } from '../../src/client/ipc-client.js';
import type { KeyholeResponse } from '../../src/sidecar/ipc-types.js';

function makeMockIPC(
  responseOverrides?: Partial<KeyholeResponse>
): { ipc: IPCClient; sendMock: ReturnType<typeof mock.fn> } {
  const ipc = Object.create(IPCClient.prototype) as IPCClient;
  const sendMock = mock.fn(
    async (_req: any): Promise<KeyholeResponse> => ({
      id: _req.id || 'test',
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"ok":true}',
      bodyEncoding: 'utf8',
      ...responseOverrides,
    })
  );
  (ipc as any).send = sendMock;
  return { ipc, sendMock };
}

describe('FakeClientRequest', () => {
  it('write() accumulates body chunks, end() triggers IPC send', async () => {
    const { ipc, sendMock } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'POST', '/api', {});

    await new Promise<void>((resolve, reject) => {
      req.on('response', () => resolve());
      req.on('error', reject);
      req.write('hello ');
      req.write('world');
      req.end();
    });

    assert.equal(sendMock.mock.calls.length, 1);
    const sent = sendMock.mock.calls[0].arguments[0];
    assert.equal(sent.body, 'hello world');
    assert.equal(sent.bodyEncoding, 'utf8');
  });

  it('pipe: readable.pipe(fakeRequest) sends body correctly', async () => {
    const { ipc, sendMock } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'POST', '/upload', {});

    const readable = new Readable({
      read() {
        this.push('piped-data');
        this.push(null);
      },
    });

    await new Promise<void>((resolve, reject) => {
      req.on('response', () => resolve());
      req.on('error', reject);
      readable.pipe(req);
    });

    assert.equal(sendMock.mock.calls.length, 1);
    const sent = sendMock.mock.calls[0].arguments[0];
    assert.equal(sent.body, 'piped-data');
  });

  it('UTF-8 text body sent as bodyEncoding: utf8', async () => {
    const { ipc, sendMock } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'POST', '/api', {
      'content-type': 'application/json',
    });

    await new Promise<void>((resolve, reject) => {
      req.on('response', () => resolve());
      req.on('error', reject);
      req.end('{"text":"hello"}');
    });

    const sent = sendMock.mock.calls[0].arguments[0];
    assert.equal(sent.bodyEncoding, 'utf8');
    assert.equal(sent.body, '{"text":"hello"}');
  });

  it('binary body sent as bodyEncoding: base64', async () => {
    const { ipc, sendMock } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'POST', '/upload', {
      'content-type': 'image/png',
    });

    const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

    await new Promise<void>((resolve, reject) => {
      req.on('response', () => resolve());
      req.on('error', reject);
      req.end(pngBytes);
    });

    const sent = sendMock.mock.calls[0].arguments[0];
    assert.equal(sent.bodyEncoding, 'base64');
    assert.equal(sent.bodyBase64, pngBytes.toString('base64'));
  });

  it('abort()/destroy() → no IPC send', async () => {
    const { ipc, sendMock } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'GET', '/api', {});

    req.write('partial');
    req.abort();

    assert.equal(req.aborted, true);
    assert.equal(sendMock.mock.calls.length, 0);
  });

  it('body > 10MB rejected via _write()', async () => {
    const { ipc } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'POST', '/api', {});

    const bigChunk = Buffer.alloc(11 * 1024 * 1024); // 11MB

    await new Promise<void>((resolve) => {
      req.on('error', (err: Error) => {
        assert.ok(err.message.includes('exceeds'));
        resolve();
      });
      req.write(bigChunk);
    });
  });

  it('body > 10MB rejected via pipe', async () => {
    const { ipc } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'POST', '/api', {});

    const bigChunk = Buffer.alloc(11 * 1024 * 1024);
    const readable = new Readable({
      read() {
        this.push(bigChunk);
        this.push(null);
      },
    });

    await new Promise<void>((resolve) => {
      req.on('error', (err: Error) => {
        assert.ok(err.message.includes('exceeds'));
        resolve();
      });
      readable.pipe(req);
    });
  });

  it('setHeader/getHeader/removeHeader work', () => {
    const { ipc } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'GET', '/', {});

    req.setHeader('X-Test', 'value');
    assert.equal(req.getHeader('X-Test'), 'value');

    req.removeHeader('X-Test');
    assert.equal(req.getHeader('X-Test'), undefined);
  });

  it('no-op methods don\'t throw', () => {
    const { ipc } = makeMockIPC();
    const req = new FakeClientRequest(ipc, 'github', 'GET', '/', {});

    assert.doesNotThrow(() => req.setTimeout(1000));
    assert.doesNotThrow(() => req.setNoDelay(true));
    assert.doesNotThrow(() => req.setSocketKeepAlive(true, 100));
    assert.doesNotThrow(() => req.flushHeaders());
  });

  it('response callback invoked with statusCode and headers', async () => {
    const { ipc } = makeMockIPC({ status: 201, headers: { 'x-req-id': '123' } });

    const response = await new Promise<any>((resolve, reject) => {
      const req = new FakeClientRequest(
        ipc, 'github', 'GET', '/', {},
        (res) => resolve(res)
      );
      req.on('error', reject);
      req.end();
    });

    assert.equal(response.statusCode, 201);
    assert.equal(response.headers['x-req-id'], '123');
  });
});
