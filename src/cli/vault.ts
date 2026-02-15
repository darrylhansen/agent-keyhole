import fs from 'fs';
import { loadConfig } from '../config/loader.js';
import { VaultStore } from '../store/vault.js';
import {
  promptSecret,
  promptConfirm,
  getConfigPath,
  getVaultPath,
  createVaultInteractive
} from './shared.js';

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

  try {
    await createVaultInteractive(vaultPath);
    console.error('  To add secrets: npx keyhole vault add <service-name>');
  } catch (err: any) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
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
    console.error('Vault unlocked\n');
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
  console.error(`\nSecret "${secretRef}" stored in vault`);
  console.error('Vault re-encrypted and saved');
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
  console.error(`\nRemoved "${secretRef}" from vault`);
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
