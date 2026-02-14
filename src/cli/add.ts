import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { loadConfig } from '../config/loader.js';
import { KeychainStore } from '../store/keychain.js';

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

  console.error(`Service: ${serviceName}`);
  console.error(`Secret ref: ${secretRef} (from keyhole.yaml)`);

  const value = await promptSecret('Enter secret value: ');

  if (!value) {
    console.error('Error: Empty secret value');
    process.exit(1);
  }

  const store = new KeychainStore();
  await store.set(secretRef, value);
  console.error(`✔ Stored "${secretRef}" in OS keychain`);

  // Verify
  try {
    await store.get(secretRef);
    console.error('✔ Verified: secret is retrievable');
  } catch {
    console.error('⚠ Warning: could not verify secret retrieval');
  }
}

async function promptSecret(prompt: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
    terminal: true
  });

  return new Promise((resolve) => {
    // Hide input by using a question with terminal mode
    (rl as any).output?.write(prompt);
    (rl as any)._writeToOutput = function () {};
    rl.question('', (answer) => {
      (rl as any).output?.write('\n');
      rl.close();
      resolve(answer);
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
