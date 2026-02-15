import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'child_process';
import { EventEmitter } from 'events';
import { spawnSidecar } from '../../src/client/spawn.js';
import { SINGLE_BEARER_CONFIG } from '../helpers/fixtures.js';

class MockChildProcess extends EventEmitter {
  killed = false;
  pid = 12345;
  receivedMessages: any[] = [];

  send(msg: any): boolean {
    this.receivedMessages.push(msg);
    return true;
  }

  kill(_signal?: string): boolean {
    this.killed = true;
    return true;
  }
}

describe('spawn', () => {
  let forkMock: ReturnType<typeof mock.fn>;
  let mockChild: MockChildProcess;

  afterEach(() => {
    forkMock?.mock?.restore();
  });

  function setupMock(): MockChildProcess {
    mockChild = new MockChildProcess();
    forkMock = mock.method(childProcess, 'fork', () => mockChild as any);
    return mockChild;
  }

  it('sends bootstrap message with OTT on spawn', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });

    // Wait a tick for the bootstrap message to be sent
    await new Promise((r) => setTimeout(r, 10));

    assert.ok(child.receivedMessages.length > 0);
    const bootstrap = child.receivedMessages[0];
    assert.equal(bootstrap.type, 'bootstrap');
    assert.ok(typeof bootstrap.ott === 'string');
    assert.ok(bootstrap.config);

    // Send ready to resolve the promise
    child.emit('message', {
      type: 'ready',
      socketPath: '/tmp/test.sock',
      state: 'ready',
    });

    const handle = await spawnPromise;
    assert.ok(handle);
  });

  it('OTT is 64-char hex (32 random bytes)', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });
    await new Promise((r) => setTimeout(r, 10));

    const ott = child.receivedMessages[0].ott;
    assert.equal(ott.length, 64);
    assert.match(ott, /^[0-9a-f]{64}$/);

    child.emit('message', { type: 'ready', socketPath: '/tmp/test.sock', state: 'ready' });
    await spawnPromise;
  });

  it('ready message resolves with SidecarHandle', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });
    await new Promise((r) => setTimeout(r, 10));

    child.emit('message', {
      type: 'ready',
      socketPath: '/tmp/keyhole-abc.sock',
      state: 'ready',
    });

    const handle = await spawnPromise;
    assert.equal(handle.socketPath, '/tmp/keyhole-abc.sock');
    assert.equal(handle.state, 'ready');
    assert.equal(handle.child, child);
    assert.equal(handle.ott.length, 64);
  });

  it('pending_unlock state propagated', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });
    await new Promise((r) => setTimeout(r, 10));

    child.emit('message', {
      type: 'ready',
      socketPath: '/tmp/keyhole-abc.sock',
      state: 'pending_unlock',
    });

    const handle = await spawnPromise;
    assert.equal(handle.state, 'pending_unlock');
  });

  it('error message rejects promise', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });
    await new Promise((r) => setTimeout(r, 10));

    child.emit('message', {
      type: 'error',
      message: 'Config validation failed',
    });

    await assert.rejects(spawnPromise, /Config validation failed/);
  });

  it('spawn timeout rejects after configured ms', async () => {
    const child = setupMock();

    // Never send ready → should timeout
    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 100 });

    await assert.rejects(spawnPromise, /failed to start within 100ms/i);
    assert.equal(child.killed, true);
  });

  it('child exit with non-zero code rejects', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });
    await new Promise((r) => setTimeout(r, 10));

    child.emit('exit', 1, null);

    await assert.rejects(spawnPromise, /exited with code 1/);
  });

  it('config serialization: Maps converted to plain objects', async () => {
    const child = setupMock();

    const spawnPromise = spawnSidecar(SINGLE_BEARER_CONFIG, { timeout: 500 });
    await new Promise((r) => setTimeout(r, 10));

    const config = child.receivedMessages[0].config;
    // _domainToService should be a plain object, not a Map
    assert.ok(!(config._domainToService instanceof Map));
    assert.equal(typeof config._domainToService, 'object');
    assert.equal(config._domainToService['api.github.com'], 'github');

    child.emit('message', { type: 'ready', socketPath: '/tmp/test.sock', state: 'ready' });
    await spawnPromise;
  });
});
