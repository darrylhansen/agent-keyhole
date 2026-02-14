import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { loadConfig } from '../config/loader.js';
import { KeychainStore } from '../store/keychain.js';

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

  const confirmed = await promptConfirm(
    `Remove "${secretRef}" from OS keychain? (y/N): `
  );

  if (!confirmed) {
    console.error('Cancelled.');
    return;
  }

  const store = new KeychainStore();
  try {
    await store.delete(secretRef);
    console.error(`✔ Removed "${secretRef}" from OS keychain`);
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

async function promptConfirm(prompt: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr
  });

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

function getConfigPath(args: string[]): string {
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    return path.resolve(args[configIdx + 1]);
  }
  return path.resolve('keyhole.yaml');
}
