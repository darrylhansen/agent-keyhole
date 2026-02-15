import fs from 'fs';
import { loadConfig } from '../config/loader.js';
import { createStore, VaultStore } from '../store/vault.js';
import {
  getConfigPath,
  getVaultPath,
  promptSecret,
  NO_STORE_GUIDANCE
} from './shared.js';

export async function listCommand(args: string[]): Promise<void> {
  const configPath = getConfigPath(args);
  if (!fs.existsSync(configPath)) {
    console.error(`Error: ${configPath} not found. Run "npx keyhole init" first.`);
    process.exit(1);
  }

  const config = await loadConfig(configPath);
  const vaultPath = getVaultPath(args);

  let store;
  try {
    store = await createStore({ vaultPath });
  } catch {
    console.error(NO_STORE_GUIDANCE);
    console.error('');
    store = null;
  }

  // If vault store, attempt unlock before checking secrets
  let vaultLocked = false;
  if (store instanceof VaultStore) {
    const passphrase = await promptSecret('Enter vault passphrase: ');
    if (!passphrase) {
      vaultLocked = true;
      console.error('Skipping secret status (vault locked).\n');
    } else {
      try {
        await store.unlock(passphrase);
      } catch (err: any) {
        vaultLocked = true;
        console.error(`Could not unlock vault: ${err.message}`);
        console.error('Showing config only (vault locked).\n');
      }
    }
  }

  console.error('Services configured in keyhole.yaml:\n');

  let storedCount = 0;
  const services = Object.entries(config.services);

  for (const [name, service] of services) {
    const firstDomain = service.domains[0];
    const domainStr =
      typeof firstDomain === 'string' ? firstDomain : firstDomain.host;
    const displayDomain =
      domainStr.length > 24 ? domainStr.substring(0, 21) + '...' : domainStr;

    const authType = service.auth.type.padEnd(8);

    let status: string;
    if (vaultLocked) {
      status = '? vault locked';
    } else if (!store) {
      status = '? no store';
    } else {
      try {
        const has = await store.has(service.auth.secret_ref);
        if (has) {
          status = '+ stored';
          storedCount++;
        } else {
          status = '- not found';
        }
      } catch {
        status = '- not found';
      }
    }

    console.error(
      `  ${name.padEnd(12)} ${displayDomain.padEnd(24)} ${authType} ${status}`
    );
  }

  console.error('');

  if (vaultLocked) {
    console.error(
      'Unlock the vault to see secret status: re-run "npx keyhole list"'
    );
  } else if (store) {
    console.error(
      `${storedCount} of ${services.length} services have secrets configured.`
    );

    if (storedCount < services.length) {
      for (const [name, service] of services) {
        const has = await store.has(service.auth.secret_ref).catch(() => false);
        if (!has) {
          console.error(`Run "npx keyhole add ${name}" to add the missing secret.`);
          break;
        }
      }
    }
  }
}
