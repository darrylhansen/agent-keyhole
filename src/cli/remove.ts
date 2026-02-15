import fs from 'fs';
import { loadConfig } from '../config/loader.js';
import { createStore, VaultStore } from '../store/vault.js';
import {
  promptSecret,
  promptConfirm,
  getConfigPath,
  getVaultPath,
  NO_STORE_GUIDANCE
} from './shared.js';

export async function removeCommand(args: string[]): Promise<void> {
  const serviceName = args.find((a) => !a.startsWith('-'));
  if (!serviceName) {
    console.error('Usage: npx keyhole remove <service>');
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
    process.exit(1);
  }

  const secretRef = service.auth.secret_ref;
  const vaultPath = getVaultPath(args);

  let store;
  try {
    store = await createStore({ vaultPath });
  } catch {
    console.error(NO_STORE_GUIDANCE);
    process.exit(1);
  }

  let passphrase: string | undefined;
  if (store instanceof VaultStore) {
    passphrase = await promptSecret('Enter vault passphrase: ');
    try {
      await store.unlock(passphrase);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  }

  const storeName = store instanceof VaultStore ? 'vault' : 'OS keychain';
  const confirmed = await promptConfirm(
    `Remove "${secretRef}" from ${storeName}? (y/N): `
  );

  if (!confirmed) {
    console.error('Cancelled.');
    return;
  }

  try {
    await store.delete(secretRef, passphrase);
    console.error(`Removed "${secretRef}" from ${storeName}`);
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}
