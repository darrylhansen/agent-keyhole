import { createStore, VaultStore } from '../store/vault.js';
import {
  promptSecret,
  getVaultPath,
  NO_STORE_GUIDANCE
} from './shared.js';

export async function getCommand(args: string[]): Promise<void> {
  const secretRef = args.find((a) => !a.startsWith('-'));
  if (!secretRef) {
    console.error('Usage: npx keyhole get <secret-ref>');
    console.error('\nRetrieve and print a stored secret value.');
    console.error('The secret is written to stdout (pipe-friendly).');
    process.exit(1);
  }

  const vaultPath = getVaultPath(args);

  let store;
  try {
    store = await createStore({ vaultPath });
  } catch {
    console.error(NO_STORE_GUIDANCE);
    process.exit(1);
  }

  // Unlock vault if needed
  if (store instanceof VaultStore) {
    const passphrase = await promptSecret('Enter vault passphrase: ');
    if (!passphrase) {
      console.error('Error: passphrase required to read from vault.');
      process.exit(1);
    }
    try {
      await store.unlock(passphrase);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  }

  let value: string;
  try {
    value = await store.get(secretRef);
  } catch {
    console.error(`Error: secret "${secretRef}" not found in store.`);
    console.error('Run "npx keyhole list" to see available secrets.');
    process.exit(1);
    return; // unreachable, for type narrowing
  }

  // Write to stdout (not stderr) so it can be piped.
  // Use write + explicit newline + drain handling to ensure output
  // is flushed before the process exits.
  const flushed = process.stdout.write(value + '\n');
  if (!flushed) {
    await new Promise<void>((resolve) => process.stdout.once('drain', resolve));
  }
}
