import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { VaultStore } from '../store/vault.js';

const MIN_PASSPHRASE_LENGTH = 12;

export const NO_STORE_GUIDANCE =
  'No secret store configured.\n' +
  '  macOS/Linux desktop: secrets are stored in your OS keychain automatically.\n' +
  '  Headless/WSL/VPS: run "npx keyhole vault create" to set up encrypted storage.';

export function getConfigPath(args: string[]): string {
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    return path.resolve(args[configIdx + 1]);
  }
  return path.resolve('keyhole.yaml');
}

export function getVaultPath(args: string[]): string {
  const vaultIdx = args.indexOf('--vault');
  if (vaultIdx !== -1 && args[vaultIdx + 1]) {
    return path.resolve(args[vaultIdx + 1]);
  }
  return path.resolve('.keyhole.vault');
}

export async function promptSecret(prompt: string): Promise<string> {
  process.stderr.write(prompt);

  // Use raw mode to suppress echo instead of readline (whose _refreshLine
  // calls cursorTo(0) + clearScreenDown on the output stream, erasing
  // any prompt text we wrote).
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
  }

  return new Promise((resolve) => {
    let input = '';

    const cleanup = () => {
      process.stdin.removeListener('data', onData);
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      process.stdin.pause();
    };

    const onData = (data: Buffer) => {
      for (const byte of data) {
        if (byte === 0x0d || byte === 0x0a) {
          // Enter
          cleanup();
          process.stderr.write('\n');
          resolve(input);
          return;
        } else if (byte === 0x03) {
          // Ctrl+C
          cleanup();
          process.stderr.write('\n');
          process.exit(130);
        } else if (byte === 0x7f || byte === 0x08) {
          // Backspace / Delete
          input = input.slice(0, -1);
        } else if (byte >= 0x20) {
          input += String.fromCharCode(byte);
        }
      }
    };

    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

export async function promptConfirm(prompt: string): Promise<boolean> {
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

/**
 * Interactive vault creation flow: prompt for passphrase, confirm, create vault.
 * Returns the passphrase so callers can reuse it for immediate unlock.
 */
export async function createVaultInteractive(
  vaultPath: string
): Promise<string> {
  console.error('Creating encrypted vault for secret storage.\n');
  console.error(`  Requirements: minimum ${MIN_PASSPHRASE_LENGTH} characters`);
  console.error('  WARNING: If you lose this passphrase, your stored secrets are');
  console.error('  unrecoverable. There is no reset or recovery mechanism.\n');

  const passphrase = await promptSecret('Enter master passphrase: ');
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(
      `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`
    );
  }

  const confirm = await promptSecret('Confirm master passphrase: ');
  if (passphrase !== confirm) {
    throw new Error('Passphrases do not match');
  }

  const vault = new VaultStore(vaultPath);
  await vault.create(passphrase);

  console.error(`\nVault created at ${vaultPath} (permissions: 0600)`);
  return passphrase;
}
