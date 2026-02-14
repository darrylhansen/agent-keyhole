import { execFileSync } from 'child_process';
import os from 'os';
import type { SecretStore } from './interface.js';

const SERVICE_NAME = 'agent-keyhole';

export class KeychainStore implements SecretStore {
  private platform: NodeJS.Platform;

  constructor() {
    this.platform = os.platform();
    if (this.platform !== 'darwin' && this.platform !== 'linux') {
      throw new Error(
        `KeychainStore is not supported on ${this.platform}. ` +
        `Use VaultStore instead: npx keyhole vault create`
      );
    }
  }

  async get(ref: string): Promise<string> {
    if (this.platform === 'darwin') {
      return this.macGet(ref);
    }
    return this.linuxGet(ref);
  }

  async set(ref: string, value: string): Promise<void> {
    if (this.platform === 'darwin') {
      return this.macSet(ref, value);
    }
    return this.linuxSet(ref, value);
  }

  async delete(ref: string): Promise<void> {
    if (this.platform === 'darwin') {
      return this.macDelete(ref);
    }
    return this.linuxDelete(ref);
  }

  async list(): Promise<string[]> {
    if (this.platform === 'darwin') {
      return this.macList();
    }
    return this.linuxList();
  }

  async has(ref: string): Promise<boolean> {
    try {
      await this.get(ref);
      return true;
    } catch {
      return false;
    }
  }

  // --- macOS (Keychain Access) ---

  private macGet(ref: string): string {
    try {
      const result = execFileSync('security', [
        'find-generic-password', '-s', SERVICE_NAME, '-a', ref, '-w'
      ], { encoding: 'utf-8' });
      return result.trim();
    } catch {
      throw new Error(`Secret not found in keychain: ${ref}`);
    }
  }

  private macSet(ref: string, value: string): void {
    // Delete first to avoid "already exists" error
    try {
      execFileSync('security', [
        'delete-generic-password', '-s', SERVICE_NAME, '-a', ref
      ], { stdio: 'ignore' });
    } catch {
      // Ignore if it doesn't exist
    }

    // Pipe secret via stdin to avoid exposure in ps output
    execFileSync('security', [
      'add-generic-password', '-s', SERVICE_NAME, '-a', ref, '-w',
      '-T', '/usr/bin/security',
      '-T', process.execPath
    ], { input: value });
  }

  private macDelete(ref: string): void {
    try {
      execFileSync('security', [
        'delete-generic-password', '-s', SERVICE_NAME, '-a', ref
      ], { stdio: 'ignore' });
    } catch {
      throw new Error(`Secret not found in keychain: ${ref}`);
    }
  }

  private macList(): string[] {
    try {
      const output = execFileSync('security', ['dump-keychain'], {
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024
      });

      const entries: string[] = [];
      const lines = output.split('\n');
      let inKeyholeEntry = false;

      for (const line of lines) {
        if (line.includes(`"svce"<blob>="${SERVICE_NAME}"`)) {
          inKeyholeEntry = true;
        }
        if (inKeyholeEntry && line.includes('"acct"<blob>="')) {
          const match = line.match(/"acct"<blob>="([^"]+)"/);
          if (match) {
            entries.push(match[1]);
            inKeyholeEntry = false;
          }
        }
      }

      return entries;
    } catch {
      return [];
    }
  }

  // --- Linux (libsecret / secret-tool) ---

  private linuxGet(ref: string): string {
    try {
      const result = execFileSync('secret-tool', [
        'lookup', 'service', SERVICE_NAME, 'account', ref
      ], { encoding: 'utf-8' });
      return result.trim();
    } catch {
      throw new Error(`Secret not found in keychain: ${ref}`);
    }
  }

  private linuxSet(ref: string, value: string): void {
    execFileSync('secret-tool', [
      'store', `--label=agent-keyhole:${ref}`,
      'service', SERVICE_NAME, 'account', ref
    ], { input: value });
  }

  private linuxDelete(ref: string): void {
    try {
      execFileSync('secret-tool', [
        'clear', 'service', SERVICE_NAME, 'account', ref
      ], { stdio: 'ignore' });
    } catch {
      throw new Error(`Secret not found in keychain: ${ref}`);
    }
  }

  private linuxList(): string[] {
    try {
      const output = execFileSync('secret-tool', [
        'search', '--all', 'service', SERVICE_NAME
      ], { encoding: 'utf-8' });

      const entries: string[] = [];
      const lines = output.split('\n');

      for (const line of lines) {
        const match = line.match(/attribute\.account\s*=\s*(.+)/);
        if (match) {
          entries.push(match[1].trim());
        }
      }

      return entries;
    } catch {
      return [];
    }
  }
}

/** Test if OS keychain is accessible */
export async function testKeychainAccess(): Promise<void> {
  const platform = os.platform();

  if (platform === 'darwin') {
    try {
      execFileSync('security', ['default-keychain'], { encoding: 'utf-8' });
    } catch {
      throw new Error('macOS Keychain is not accessible');
    }
  } else if (platform === 'linux') {
    try {
      execFileSync('which', ['secret-tool'], { encoding: 'utf-8' });
    } catch {
      throw new Error(
        'secret-tool is not installed. Install it with:\n' +
        '  sudo apt install libsecret-tools   (Debian/Ubuntu)\n' +
        '  sudo dnf install libsecret          (Fedora)\n' +
        'Or use the encrypted vault: npx keyhole vault create'
      );
    }
  } else {
    throw new Error(`Unsupported platform for keychain: ${platform}`);
  }
}
