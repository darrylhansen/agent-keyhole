import fs from 'fs';
import path from 'path';
import { loadConfig } from '../config/loader.js';
import { createStore } from '../store/vault.js';

export async function listCommand(args: string[]): Promise<void> {
  const configPath = getConfigPath(args);
  if (!fs.existsSync(configPath)) {
    console.error(`Error: ${configPath} not found. Run "npx keyhole init" first.`);
    process.exit(1);
  }

  const config = await loadConfig(configPath);

  let store;
  try {
    store = await createStore();
  } catch {
    console.error('Warning: Could not access secret store. Showing config only.\n');
    store = null;
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

    let status = '? unknown';
    if (store) {
      try {
        const has = await store.has(service.auth.secret_ref);
        if (has) {
          status = '✔ stored';
          storedCount++;
        } else {
          status = '✗ not found';
        }
      } catch {
        status = '✗ not found';
      }
    }

    console.error(
      `  ${name.padEnd(12)} ${displayDomain.padEnd(24)} ${authType} ${status}`
    );
  }

  console.error('');

  if (store) {
    console.error(
      `${storedCount} of ${services.length} services have secrets configured.`
    );

    if (storedCount < services.length) {
      const missing = services.filter(
        async ([_, s]) => {
          try {
            return !(await store!.has(s.auth.secret_ref));
          } catch {
            return true;
          }
        }
      );
      // Show first missing service as hint
      for (const [name] of services) {
        try {
          const service = config.services[name];
          const has = store ? await store.has(service.auth.secret_ref) : false;
          if (!has) {
            console.error(`Run "npx keyhole add ${name}" to add the missing secret.`);
            break;
          }
        } catch {
          console.error(`Run "npx keyhole add ${name}" to add the missing secret.`);
          break;
        }
      }
    }
  }
}

function getConfigPath(args: string[]): string {
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    return path.resolve(args[configIdx + 1]);
  }
  return path.resolve('keyhole.yaml');
}
