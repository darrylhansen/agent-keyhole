import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { SecretStore } from './interface.js';

const SCRYPT_KEYLEN = 32;
const SCRYPT_COST = 16384;
const SCRYPT_BLOCK = 8;
const SCRYPT_PARALLEL = 1;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

interface VaultPayload {
  version: number;
  created_at: string;
  secrets: Record<string, string>;
}

export class VaultStore implements SecretStore {
  private vaultPath: string;
  private secrets: Map<string, string> | null = null;

  constructor(vaultPath?: string) {
    this.vaultPath = vaultPath || path.resolve('.keyhole.vault');
  }

  /** Derive AES-256 key from passphrase using scrypt */
  private deriveKey(passphrase: string, salt: Buffer): Buffer {
    return crypto.scryptSync(passphrase, salt, SCRYPT_KEYLEN, {
      N: SCRYPT_COST,
      r: SCRYPT_BLOCK,
      p: SCRYPT_PARALLEL
    });
  }

  /** Create a new vault file */
  async create(passphrase: string): Promise<void> {
    if (fs.existsSync(this.vaultPath)) {
      throw new Error(`Vault already exists at ${this.vaultPath}`);
    }

    this.secrets = new Map();
    await this.saveVault(passphrase, {
      version: 1,
      created_at: new Date().toISOString(),
      secrets: {}
    });
    fs.chmodSync(this.vaultPath, 0o600);
  }

  /** Unlock the vault – read and decrypt into RAM */
  async unlock(passphrase: string): Promise<void> {
    if (!fs.existsSync(this.vaultPath)) {
      throw new Error(`Vault not found at ${this.vaultPath}`);
    }

    const raw = fs.readFileSync(this.vaultPath);
    const salt = raw.subarray(0, SALT_LENGTH);
    const iv = raw.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const authTag = raw.subarray(
      SALT_LENGTH + IV_LENGTH,
      SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH
    );
    const ciphertext = raw.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

    const key = this.deriveKey(passphrase, salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted: string;
    try {
      decrypted =
        decipher.update(ciphertext, undefined, 'utf8') +
        decipher.final('utf8');
    } catch {
      throw new Error('Invalid passphrase or corrupted vault');
    }

    const payload = JSON.parse(decrypted) as VaultPayload;
    this.secrets = new Map(Object.entries(payload.secrets));
  }

  /** Save current state to encrypted vault file using atomic write */
  private async saveVault(
    passphrase: string,
    payload?: VaultPayload
  ): Promise<void> {
    const data = payload || {
      version: 1,
      created_at: new Date().toISOString(),
      secrets: Object.fromEntries(this.secrets!)
    };

    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = this.deriveKey(passphrase, salt);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = JSON.stringify(data);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    const output = Buffer.concat([salt, iv, authTag, ciphertext]);
    const tempPath = this.vaultPath + '.tmp';
    fs.writeFileSync(tempPath, output);
    fs.chmodSync(tempPath, 0o600);
    fs.renameSync(tempPath, this.vaultPath);
  }

  async get(ref: string): Promise<string> {
    if (!this.secrets) throw new Error('Vault is locked – call unlock() first');
    const value = this.secrets.get(ref);
    if (!value) throw new Error(`Secret not found in vault: ${ref}`);
    return value;
  }

  async set(ref: string, value: string, passphrase?: string): Promise<void> {
    if (!passphrase) throw new Error('Passphrase required to save vault');
    if (!this.secrets) await this.unlock(passphrase);
    this.secrets!.set(ref, value);
    await this.saveVault(passphrase);
  }

  async delete(ref: string, passphrase?: string): Promise<void> {
    if (!passphrase) throw new Error('Passphrase required to save vault');
    if (!this.secrets) await this.unlock(passphrase);
    this.secrets!.delete(ref);
    await this.saveVault(passphrase);
  }

  async list(): Promise<string[]> {
    if (!this.secrets) throw new Error('Vault is locked – call unlock() first');
    return Array.from(this.secrets.keys());
  }

  async has(ref: string): Promise<boolean> {
    if (!this.secrets) throw new Error('Vault is locked – call unlock() first');
    return this.secrets.has(ref);
  }

  async setMany(
    entries: [ref: string, value: string][],
    passphrase?: string
  ): Promise<void> {
    if (!passphrase) throw new Error('Passphrase required to save vault');
    if (!this.secrets) await this.unlock(passphrase);
    for (const [ref, value] of entries) {
      this.secrets!.set(ref, value);
    }
    await this.saveVault(passphrase);
  }

  get isLocked(): boolean {
    return this.secrets === null;
  }
}

/** Create a secret store based on options and environment detection */
export async function createStore(options?: {
  store?: 'keychain' | 'vault';
  vaultPath?: string;
}): Promise<SecretStore> {
  if (options?.store === 'vault') return new VaultStore(options.vaultPath);

  if (options?.store === 'keychain') {
    const { KeychainStore } = await import('./keychain.js');
    return new KeychainStore();
  }

  // Auto-detect: keychain → vault
  try {
    const { testKeychainAccess, KeychainStore } = await import('./keychain.js');
    await testKeychainAccess();
    return new KeychainStore();
  } catch {
    const vaultPath = options?.vaultPath || '.keyhole.vault';
    if (fs.existsSync(vaultPath)) {
      console.warn(
        '[keyhole] OS keychain not available, using encrypted vault'
      );
      return new VaultStore(vaultPath);
    }
    throw new Error(
      'No secret store available. Either:\n' +
        '  - Run on a system with an OS keychain (macOS Keychain, Linux secret-tool)\n' +
        '  - Create an encrypted vault: npx keyhole vault create'
    );
  }
}
