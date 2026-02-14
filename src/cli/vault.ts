import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { loadConfig } from '../config/loader.js';
import { VaultStore } from '../store/vault.js';

const MIN_PASSPHRASE_LENGTH = 12;

export async function vaultCommand(args: string[]): Promise<void> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'create':
      await vaultCreate(args.slice(1));
      break;
    case 'add':
      await vaultAdd(args.slice(1));
      break;
    case 'remove':
      await vaultRemove(args.slice(1));
      break;
    case 'list':
      await vaultList(args.slice(1));
      break;
    default:
      console.error('Usage: npx keyhole vault <create|add|remove|list>');
      process.exit(1);
  }
}

async function vaultCreate(args: string[]): Promise<void> {
  const vaultPath = getVaultPath(args);

  if (fs.existsSync(vaultPath)) {
    console.error(`Error: Vault already exists at ${vaultPath}`);
    process.exit(1);
  }

  const passphrase = await promptSecret('Enter master passphrase: ');
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    console.error(
      `Error: Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`
    );
    process.exit(1);
  }

  const confirm = await promptSecret('Confirm master passphrase: ');
  if (passphrase !== confirm) {
    console.error('Error: Passphrases do not match');
    process.exit(1);
  }

  const vault = new VaultStore(vaultPath);
  await vault.create(passphrase);

  console.error(`\n✔ Vault created at ${vaultPath} (permissions: 0600)`);
  console.error('  To add secrets: npx keyhole vault add <service-name>');
}

async function vaultAdd(args: string[]): Promise<void> {
  const serviceName = args.find((a) => !a.startsWith('-'));
  if (!serviceName) {
    console.error('Usage: npx keyhole vault add <service>');
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

  const vaultPath = getVaultPath(args);
  if (!fs.existsSync(vaultPath)) {
    console.error(`Error: Vault not found at ${vaultPath}. Run "npx keyhole vault create" first.`);
    process.exit(1);
  }

  const passphrase = await promptSecret('Enter master passphrase: ');
  const vault = new VaultStore(vaultPath);

  try {
    await vault.unlock(passphrase);
    console.error('✔ Vault unlocked\n');
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
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

  await vault.set(secretRef, value, passphrase);
  console.error(`\n✔ Secret "${secretRef}" stored in vault`);
  console.error('✔ Vault re-encrypted and saved');
}

async function vaultRemove(args: string[]): Promise<void> {
  const serviceName = args.find((a) => !a.startsWith('-'));
  if (!serviceName) {
    console.error('Usage: npx keyhole vault remove <service>');
    process.exit(1);
  }

  const configPath = getConfigPath(args);
  if (!fs.existsSync(configPath)) {
    console.error(`Error: ${configPath} not found.`);
    process.exit(1);
  }

  const config = await loadConfig(configPath);
  const service = config.services[serviceName];
  if (!service) {
    console.error(`Error: Service "${serviceName}" not found in ${configPath}`);
    process.exit(1);
  }

  const vaultPath = getVaultPath(args);
  const passphrase = await promptSecret('Enter master passphrase: ');
  const vault = new VaultStore(vaultPath);

  try {
    await vault.unlock(passphrase);
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  const secretRef = service.auth.secret_ref;
  const confirmed = await promptConfirm(
    `Remove "${secretRef}" from vault? (y/N): `
  );
  if (!confirmed) {
    console.error('Cancelled.');
    return;
  }

  await vault.delete(secretRef, passphrase);
  console.error(`\n✔ Removed "${secretRef}" from vault`);
}

async function vaultList(args: string[]): Promise<void> {
  const vaultPath = getVaultPath(args);
  if (!fs.existsSync(vaultPath)) {
    console.error(`Error: Vault not found at ${vaultPath}`);
    process.exit(1);
  }

  const passphrase = await promptSecret('Enter master passphrase: ');
  const vault = new VaultStore(vaultPath);

  try {
    await vault.unlock(passphrase);
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  const secrets = await vault.list();
  console.error(`\nSecrets in vault:`);
  for (const ref of secrets) {
    console.error(`  ${ref}`);
  }
  console.error(`\n${secrets.length} secrets stored.`);

  // Check for missing secrets from config
  const configPath = getConfigPath(args);
  if (fs.existsSync(configPath)) {
    try {
      const config = await loadConfig(configPath);
      const configRefs = new Set(
        Object.values(config.services).map((s) => s.auth.secret_ref)
      );
      const vaultRefs = new Set(secrets);

      for (const [name, service] of Object.entries(config.services)) {
        if (!vaultRefs.has(service.auth.secret_ref)) {
          console.error(
            `Missing: ${service.auth.secret_ref} (service "${name}" configured but not in vault)`
          );
        }
      }
    } catch {
      // Config not available, skip
    }
  }
}

async function promptSecret(prompt: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
    terminal: true
  });

  return new Promise((resolve) => {
    (rl as any).output?.write(prompt);
    (rl as any)._writeToOutput = function () {};
    rl.question('', (answer) => {
      (rl as any).output?.write('\n');
      rl.close();
      resolve(answer);
    });
  });
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

function getVaultPath(args: string[]): string {
  const vaultIdx = args.indexOf('--vault');
  if (vaultIdx !== -1 && args[vaultIdx + 1]) {
    return path.resolve(args[vaultIdx + 1]);
  }
  return path.resolve('.keyhole.vault');
}

function getConfigPath(args: string[]): string {
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    return path.resolve(args[configIdx + 1]);
  }
  return path.resolve('keyhole.yaml');
}
