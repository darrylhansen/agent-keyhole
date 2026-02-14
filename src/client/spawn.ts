import { fork, type ChildProcess } from 'child_process';
import crypto from 'crypto';
import path from 'path';
import { IPCClient } from './ipc-client.js';
import type { ParsedConfig } from '../config/schema.js';
import type { ReadyMessage, ErrorMessage } from '../sidecar/ipc-types.js';

export interface SidecarHandle {
  child: ChildProcess;
  socketPath: string;
  ott: string;
  state: 'ready' | 'pending_unlock';
}

export interface SpawnOptions {
  store?: 'keychain' | 'vault';
  vaultPassphrase?: string;
  agent?: string;
  timeout?: number;
  autoRestart?: boolean;
}

/**
 * Spawn the sidecar child process and wait for it to become ready.
 */
export async function spawnSidecar(
  config: ParsedConfig,
  options: SpawnOptions = {}
): Promise<SidecarHandle> {
  const ott = crypto.randomBytes(32).toString('hex');

  // Resolve the sidecar entry point relative to this file
  const sidecarEntry = path.resolve(
    __dirname,
    '../sidecar/process.js'
  );

  const env: Record<string, string> = {};
  if (options.store) {
    env.KEYHOLE_STORE = options.store;
  }

  const child = fork(sidecarEntry, [], {
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    env: { ...env, NODE_ENV: process.env.NODE_ENV }
  });

  // Send bootstrap message
  const bootstrapMsg = {
    type: 'bootstrap' as const,
    ott,
    config: serializeConfig(config),
    vaultPassphrase: options.vaultPassphrase,
    agent: options.agent
  };

  return new Promise<SidecarHandle>((resolve, reject) => {
    const timeoutMs = options.timeout || 15_000;
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Sidecar failed to start within ${timeoutMs}ms`));
    }, timeoutMs);

    child.on('message', (msg: any) => {
      if (msg.type === 'ready') {
        clearTimeout(timer);
        resolve({
          child,
          socketPath: msg.socketPath,
          ott,
          state: msg.state
        });
      }
      if (msg.type === 'error') {
        clearTimeout(timer);
        reject(new Error(msg.message));
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 && code !== null) {
        reject(
          new Error(
            `Sidecar exited with code ${code}${signal ? ` (signal: ${signal})` : ''}`
          )
        );
      }
    });

    child.send(bootstrapMsg);
  });
}

/**
 * Serialize config for IPC transport. Maps don't survive JSON serialization,
 * so convert them to plain objects.
 */
function serializeConfig(config: ParsedConfig): any {
  return {
    ...config,
    _domainToService: Object.fromEntries(config._domainToService),
    _secretRefs: config._secretRefs
  };
}
