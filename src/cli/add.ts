import fs from 'fs';
import { loadConfig } from '../config/loader.js';
import { createStore, VaultStore } from '../store/vault.js';
import type { SecretStore } from '../store/interface.js';
import {
  promptSecret,
  promptConfirm,
  getConfigPath,
  getVaultPath,
  createVaultInteractive,
  NO_STORE_GUIDANCE
} from './shared.js';

export async function addCommand(args: string[]): Promise<void> {
  const serviceName = args.find((a) => !a.startsWith('-'));
  if (!serviceName) {
    console.error('Usage: npx keyhole add <service>');
    process.exit(1);
  }

  const configPath = getConfigPath(args);
  if (!fs.existsSync(configPath)) {
    console.error(`Error: ${configPath} not found. Run "npx keyhole init" first.`);
    process.exit(1);
  }

  const config = await loadConfig(configPath);
  const service = config.services[serviceName];
  if (!service) {
    console.error(`Error: Service "${serviceName}" not found in ${configPath}`);
    console.error(`Available services: ${Object.keys(config.services).join(', ')}`);
    process.exit(1);
  }

  const secretRef = service.auth.secret_ref;
  const vaultPath = getVaultPath(args);

  // Obtain a secret store
  let store: SecretStore;
  let vaultPassphrase: string | undefined;

  try {
    store = await createStore({ vaultPath });
  } catch {
    // No keychain and no vault — offer to create one inline
    console.error('No OS keychain detected and no vault found.');
    const create = await promptConfirm('Create an encrypted vault now? (Y/n): ');
    if (!create) {
      console.error(NO_STORE_GUIDANCE);
      process.exit(1);
    }

    try {
      vaultPassphrase = await createVaultInteractive(vaultPath);
      store = await createStore({ store: 'vault', vaultPath });
      await (store as VaultStore).unlock(vaultPassphrase);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  }

  // If store is a vault and we haven't unlocked it yet, prompt for passphrase
  if (store instanceof VaultStore && !vaultPassphrase) {
    vaultPassphrase = await promptSecret('Enter vault passphrase: ');
    try {
      await store.unlock(vaultPassphrase);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  }

  console.error(`Service: ${serviceName}`);
  console.error(`Secret ref: ${secretRef} (from keyhole.yaml)`);

  const value = await promptSecret('Enter secret value: ');

  if (!value) {
    console.error('Error: Empty secret value');
    process.exit(1);
  }

  await store.set(secretRef, value, vaultPassphrase);
  const storeName = store instanceof VaultStore ? 'vault' : 'OS keychain';
  console.error(`Stored "${secretRef}" in ${storeName}`);

  // Verify
  try {
    await store.get(secretRef);
    console.error('Verified: secret is retrievable');
  } catch {
    console.error('Warning: could not verify secret retrieval');
  }
}
