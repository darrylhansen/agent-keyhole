/**
 * Sidecar process entry point.
 * This file runs in the CHILD process, spawned by the parent via fork().
 */
import type { SecretStore } from '../store/interface.js';
import { VaultStore, createStore } from '../store/vault.js';
import { startIPCServer, stopIPCServer, updateServerHandlers } from './ipc-server.js';
import { RequestBuilder } from './request-builder.js';
import { ResponseMasker } from './response-masker.js';
import { AuditLogger } from './audit-logger.js';
import { sendBootAlert } from './alerting.js';
import type { ParsedConfig } from '../config/schema.js';
import type { BootstrapMessage, UnlockMessage } from './ipc-types.js';

type SidecarState = 'booting' | 'pending_unlock' | 'ready' | 'shutting_down';

let state: SidecarState = 'booting';
let store: SecretStore;
let secrets: Map<string, string>;
let builder: RequestBuilder;
let masker: ResponseMasker;
let config: ParsedConfig;
let logger: AuditLogger;
let socketPath: string;

process.on('message', async (msg: any) => {
  if (msg.type === 'bootstrap') {
    await bootstrap(msg as BootstrapMessage);
  }
  if (msg.type === 'unlock') {
    await handleUnlock(msg as UnlockMessage);
  }
  if (msg.type === 'shutdown') {
    await shutdown();
    process.exit(0);
  }
});

async function bootstrap(msg: BootstrapMessage): Promise<void> {
  config = msg.config as ParsedConfig;

  // Reconstruct Maps from serialized config (Maps don't survive JSON)
  if (config._domainToService && !(config._domainToService instanceof Map)) {
    config._domainToService = new Map(
      Object.entries(config._domainToService as any)
    );
  }

  logger = new AuditLogger(config.logging);
  logger.info('sidecar.boot');

  // 1. Create secret store
  const storeType = process.env.KEYHOLE_STORE as 'keychain' | 'vault' | undefined;
  store = await createStore({
    store: storeType,
    vaultPath: config.vaultPath
  });

  // 2. Attempt to resolve secrets
  if (store instanceof VaultStore) {
    if (msg.vaultPassphrase) {
      try {
        await store.unlock(msg.vaultPassphrase);
        // Best-effort clearing of passphrase variable binding
        // Note: V8 string immutability means the original string persists in heap until GC
        msg.vaultPassphrase = '\0'.repeat(msg.vaultPassphrase.length);
      } catch (err: any) {
        process.send!({
          type: 'error',
          message: `Vault unlock failed: ${err.message}`
        });
        process.exit(1);
      }
      await resolveSecrets();
    } else {
      // No passphrase – enter PENDING_UNLOCK state
      state = 'pending_unlock';
      logger.warn('vault.pending_unlock');

      // Build agent services map for multi-agent access control
      const agentServices = buildAgentServicesMap(config, msg.agent);

      socketPath = await startIPCServer(
        msg.ott,
        null,
        null,
        logger,
        config.socket_dir,
        agentServices
      );

      process.send!({
        type: 'ready',
        socketPath,
        state: 'pending_unlock'
      });

      await sendBootAlert(config);
      return;
    }
  } else {
    await resolveSecrets();
  }

  // 3. Create request builder and response masker
  builder = new RequestBuilder(config, secrets);
  masker = new ResponseMasker(config, secrets);

  // 4. Start IPC server
  const agentServices = buildAgentServicesMap(config, msg.agent);
  socketPath = await startIPCServer(
    msg.ott,
    builder,
    masker,
    logger,
    config.socket_dir,
    agentServices
  );

  // 5. Signal ready
  state = 'ready';
  logger.info('sidecar.ready');
  process.send!({ type: 'ready', socketPath, state: 'ready' });
}

async function resolveSecrets(): Promise<void> {
  secrets = new Map<string, string>();
  for (const [name, service] of Object.entries(config.services)) {
    try {
      const secret = await store.get(service.auth.secret_ref);
      secrets.set(service.auth.secret_ref, secret);
      logger.debug('secret.resolved', { service: name });
    } catch (err: any) {
      logger.error('secret.missing', {
        service: name,
        error: err.message
      });
      process.send!({
        type: 'error',
        message: `Missing secret for service "${name}": ${err.message}`
      });
      process.exit(1);
    }
  }
}

async function handleUnlock(msg: UnlockMessage): Promise<void> {
  if (state !== 'pending_unlock') {
    process.send!({
      type: 'error',
      message: 'Sidecar is not in pending_unlock state'
    });
    return;
  }

  let passphrase = msg.passphrase;

  try {
    await (store as VaultStore).unlock(passphrase);
    // Best-effort clearing
    passphrase = '\0'.repeat(passphrase.length);

    await resolveSecrets();
    builder = new RequestBuilder(config, secrets);
    masker = new ResponseMasker(config, secrets);
    updateServerHandlers(builder, masker);

    state = 'ready';
    logger.info('vault.unlocked');
    process.send!({ type: 'unlocked', state: 'ready' });
  } catch (err: any) {
    logger.error('vault.unlock_failed', { error: err.message });
    process.send!({
      type: 'error',
      message: `Vault unlock failed: ${err.message}`
    });
  }
}

async function shutdown(): Promise<void> {
  state = 'shutting_down';
  logger.info('sidecar.shutdown');
  await stopIPCServer(socketPath);
}

function buildAgentServicesMap(
  config: ParsedConfig,
  agent?: string
): Map<string, string[]> | undefined {
  if (!config.agents) return undefined;

  const map = new Map<string, string[]>();
  for (const [agentName, agentConfig] of Object.entries(config.agents)) {
    map.set(agentName, agentConfig.services);
  }
  return map;
}
