import { EventEmitter } from 'events';
import { loadConfig } from './config/loader.js';
import { spawnSidecar, type SidecarHandle } from './client/spawn.js';
import { IPCClient } from './client/ipc-client.js';
import { Interceptor } from './client/interceptor.js';
import { createClient, type KeyholeClient } from './client/create-client.js';
import { generateSafeEnv, generateSafeEnvForService } from './client/safe-env.js';
import type { ParsedConfig } from './config/schema.js';

// Re-export types
export type { KeyholeClient } from './client/create-client.js';
export type {
  KeyholeConfig,
  ServiceConfig,
  AuthConfig,
  AgentConfig,
  ParsedConfig,
  HeuristicConfig
} from './config/schema.js';

export interface KeyholeOptions {
  /** Path to keyhole.yaml. Default: './keyhole.yaml' */
  config?: string;

  /** Patch http/https/fetch for transparent interception. Default: false */
  autoPatch?: boolean;

  /** Secret store to use. Default: auto-detect (keychain → vault) */
  store?: 'keychain' | 'vault';

  /** Path to vault file. Default: '.keyhole.vault' */
  vaultPath?: string;

  /** Vault passphrase. If not provided with vault store, enters PENDING_UNLOCK. */
  vaultPassphrase?: string;

  /** Agent identity for multi-agent mode. */
  agent?: string;

  /** Request timeout in milliseconds. Default: 30000 */
  timeout?: number;

  /** Auto-restart sidecar on crash. Default: false */
  autoRestart?: boolean;
}

export interface RedactionEvent {
  service: string;
  path: string;
  layer: 'header' | 'known_secret' | 'heuristic' | 'pattern' | 'json_path';
  count: number;
}

export interface Keyhole {
  createClient(serviceName: string): KeyholeClient;
  getSafeEnv(): Record<string, string>;
  getSafeEnv(serviceName: string): Record<string, string>;
  installInterceptor(): void;
  uninstallInterceptor(): void;
  unlock(passphrase: string): Promise<void>;
  readonly state: 'ready' | 'pending_unlock' | 'error';
  shutdown(): Promise<void>;
  on(event: 'error', listener: (err: Error) => void): void;
  on(event: 'redaction', listener: (info: RedactionEvent) => void): void;
  on(event: 'restarted', listener: () => void): void;
  on(event: 'unlocked', listener: () => void): void;
}

class KeyholeInstance extends EventEmitter implements Keyhole {
  private config: ParsedConfig;
  private options: KeyholeOptions;
  private handle: SidecarHandle;
  private ipcClient: IPCClient;
  private interceptor: Interceptor;
  private _state: 'ready' | 'pending_unlock' | 'error';

  constructor(
    config: ParsedConfig,
    options: KeyholeOptions,
    handle: SidecarHandle,
    ipcClient: IPCClient
  ) {
    super();
    this.config = config;
    this.options = options;
    this.handle = handle;
    this.ipcClient = ipcClient;
    this._state = handle.state;
    this.interceptor = new Interceptor(ipcClient, config);

    // Set up crash recovery
    this.handle.child.on('exit', (code, signal) => {
      if (code !== 0 && code !== null && this._state !== 'error') {
        this._state = 'error';
        this.emit('error', new Error(
          `Sidecar crashed with code ${code}${signal ? ` (signal: ${signal})` : ''}`
        ));

        if (options.autoRestart) {
          this.restart().catch((err) => {
            this.emit('error', err);
          });
        }
      }
    });

    // Auto-patch if requested
    if (options.autoPatch) {
      this.installInterceptor();
    }
  }

  get state(): 'ready' | 'pending_unlock' | 'error' {
    return this._state;
  }

  createClient(serviceName: string): KeyholeClient {
    return createClient(this.ipcClient, serviceName);
  }

  getSafeEnv(serviceName?: string): Record<string, string> {
    if (serviceName) {
      return generateSafeEnvForService(this.config, serviceName);
    }
    return generateSafeEnv(this.config);
  }

  installInterceptor(): void {
    this.interceptor.install();
  }

  uninstallInterceptor(): void {
    this.interceptor.uninstall();
  }

  async unlock(passphrase: string): Promise<void> {
    if (this._state !== 'pending_unlock') {
      throw new Error('Keyhole is not in pending_unlock state');
    }

    return new Promise((resolve, reject) => {
      const handler = (msg: any) => {
        if (msg.type === 'unlocked') {
          this.handle.child.removeListener('message', handler);
          this._state = 'ready';
          this.emit('unlocked');
          resolve();
        }
        if (msg.type === 'error' && msg.message?.includes('unlock')) {
          this.handle.child.removeListener('message', handler);
          reject(new Error(msg.message));
        }
      };

      this.handle.child.on('message', handler);
      this.handle.child.send({ type: 'unlock', passphrase });
    });
  }

  async shutdown(): Promise<void> {
    this.uninstallInterceptor();
    await this.ipcClient.disconnect();

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.handle.child.kill('SIGKILL');
        resolve();
      }, 5000);

      this.handle.child.on('exit', () => {
        clearTimeout(timer);
        resolve();
      });

      this.handle.child.send({ type: 'shutdown' });
    });
  }

  private async restart(): Promise<void> {
    try {
      this.handle = await spawnSidecar(this.config, {
        store: this.options.store,
        vaultPassphrase: this.options.vaultPassphrase,
        agent: this.options.agent,
        timeout: this.options.timeout
      });

      await this.ipcClient.updateConnection(
        this.handle.socketPath,
        this.handle.ott
      );

      this._state = this.handle.state;

      // Re-attach crash handler
      this.handle.child.on('exit', (code, signal) => {
        if (code !== 0 && code !== null && this._state !== 'error') {
          this._state = 'error';
          this.emit('error', new Error(
            `Sidecar crashed with code ${code}`
          ));
          if (this.options.autoRestart) {
            this.restart().catch((err) => this.emit('error', err));
          }
        }
      });

      this.emit('restarted');
    } catch (err) {
      this._state = 'error';
      throw err;
    }
  }
}

/**
 * Create a Keyhole instance. This spawns a sidecar process and establishes
 * IPC communication.
 */
export async function createKeyhole(
  options: KeyholeOptions = {}
): Promise<Keyhole> {
  const configPath = options.config || './keyhole.yaml';
  const config = await loadConfig(configPath);

  // Pass vault path through to config for sidecar
  if (options.vaultPath) {
    config.vaultPath = options.vaultPath;
  }

  const handle = await spawnSidecar(config, {
    store: options.store,
    vaultPassphrase: options.vaultPassphrase,
    agent: options.agent,
    timeout: options.timeout,
    autoRestart: options.autoRestart
  });

  const ipcClient = new IPCClient(handle.socketPath, handle.ott, {
    timeout: options.timeout,
    agent: options.agent
  });
  await ipcClient.connect();

  return new KeyholeInstance(config, options, handle, ipcClient);
}
