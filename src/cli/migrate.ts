import fs from 'fs';
import path from 'path';
import { loadConfig } from '../config/loader.js';
import { createStore, VaultStore } from '../store/vault.js';
import type { SecretStore } from '../store/interface.js';
import type { ParsedConfig } from '../config/schema.js';
import {
  discoverFiles,
  parseEnvFile,
  parseJsonFile,
  type ExtractedEntry,
  type SourceFile,
} from './migrate-parsers.js';
import {
  detectSecrets,
  findDuplicates,
  type SecretCandidate,
} from './migrate-detect.js';
import {
  promptSecret,
  promptConfirm,
  getConfigPath,
  getVaultPath,
  createVaultInteractive,
  NO_STORE_GUIDANCE,
} from './shared.js';

export async function migrateCommand(args: string[]): Promise<void> {
  const dryRun = args.includes('--dry-run');
  const noCleanup = args.includes('--no-cleanup');
  const configPath = getConfigPath(args);

  // Step 1: Load config if available
  let config: ParsedConfig | undefined;
  if (fs.existsSync(configPath)) {
    try {
      config = await loadConfig(configPath);
    } catch (err: any) {
      console.error(`Warning: Could not load ${configPath}: ${err.message}`);
    }
  } else {
    console.error(`Note: ${configPath} not found — skipping service matching.`);
  }

  // Step 2: Discover source files
  const cwd = process.cwd();
  const found = discoverFiles(cwd);

  if (found.length === 0) {
    console.error('No supported secret files found (.env, .env.local, etc.)');
    return;
  }

  console.error(`\nScanning ${found.length} file(s):`);
  for (const sf of found) {
    console.error(`  ${sf.filename}`);
  }

  // Step 3: Extract all entries from discovered files
  const allEntries: ExtractedEntry[] = [];
  for (const sf of found) {
    const fullPath = path.join(cwd, sf.filename);

    // Check for empty files
    const stat = fs.statSync(fullPath);
    if (stat.size === 0) {
      console.error(`  ${sf.filename}: empty, skipping`);
      continue;
    }

    const entries =
      sf.format === 'env'
        ? parseEnvFile(fullPath)
        : parseJsonFile(fullPath, sf.jsonRoot);

    allEntries.push(...entries);
  }

  if (allEntries.length === 0) {
    console.error('\nNo key-value pairs found in scanned files.');
    return;
  }

  // Step 4: Detect secrets and match to services
  const candidates = detectSecrets(allEntries, config);
  const secrets = candidates.filter((c) => c.isSecret);
  const skipped = candidates.filter((c) => !c.isSecret);

  if (secrets.length === 0) {
    console.error('\nNo secrets detected in scanned files.');
    return;
  }

  // Step 5: Check for duplicates
  const dupes = findDuplicates(secrets);

  // Step 6: Interactive confirmation
  console.error(`\nFound ${secrets.length} secret(s) in ${found.length} file(s):\n`);

  // Group by file
  const byFile = new Map<string, SecretCandidate[]>();
  for (const c of candidates) {
    const group = byFile.get(c.entry.file) || [];
    group.push(c);
    byFile.set(c.entry.file, group);
  }

  for (const [file, items] of byFile) {
    console.error(`  ${file}:`);
    for (const c of items) {
      const leafKey = c.entry.key.includes('.')
        ? c.entry.key.split('.').pop()!
        : c.entry.key;

      if (c.isSecret) {
        const serviceInfo = c.matchedService
          ? `(matched service: ${c.matchedService})`
          : '(no matching service)';
        const refPadded = c.secretRef.padEnd(20);
        console.error(
          `    + ${leafKey.padEnd(22)} -> secret_ref: ${refPadded} ${serviceInfo}`
        );
      } else {
        console.error(
          `    - ${leafKey.padEnd(22)} -> skipped (${c.skipReason})`
        );
      }
    }
    console.error('');
  }

  // Warn about duplicates
  if (dupes.size > 0) {
    console.error('Duplicate secrets found across files:');
    for (const [ref, group] of dupes) {
      const files = group.map((c) => c.entry.file).join(', ');
      console.error(`  ${ref}: found in ${files} (first occurrence will be used)`);
    }
    console.error('');
  }

  if (dryRun) {
    console.error('Dry run — no changes made.');
    return;
  }

  const confirmed = await promptConfirm(
    `Import ${secrets.length} secret(s) into Keyhole store? (Y/n): `
  );
  if (!confirmed) {
    console.error('Cancelled.');
    return;
  }

  // Step 7: Obtain store
  const vaultPath = getVaultPath(args);
  let store: SecretStore;
  let passphrase: string | undefined;

  try {
    store = await createStore({ vaultPath });
  } catch {
    console.error(NO_STORE_GUIDANCE);
    const createVault = await promptConfirm(
      '\nCreate an encrypted vault now? (Y/n): '
    );
    if (!createVault) {
      console.error('Run "npx keyhole vault create" manually, then re-run migrate.');
      process.exit(1);
    }

    passphrase = await createVaultInteractive(vaultPath);
    store = await createStore({ vaultPath });
  }

  // Unlock vault if needed
  if (store instanceof VaultStore && !passphrase) {
    passphrase = await promptSecret('Enter vault passphrase: ');
    try {
      await store.unlock(passphrase);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  }

  // Step 8: Check for existing secrets and import
  // Deduplicate — keep first occurrence per secret_ref
  const seen = new Set<string>();
  const toImport: SecretCandidate[] = [];
  for (const c of secrets) {
    if (seen.has(c.secretRef)) continue;
    seen.add(c.secretRef);
    toImport.push(c);
  }

  // Check for pre-existing secrets in store
  const overwriteRefs: string[] = [];
  for (const c of toImport) {
    try {
      const exists = await store.has(c.secretRef);
      if (exists) {
        overwriteRefs.push(c.secretRef);
      }
    } catch {
      // store may need unlock, continue
    }
  }

  if (overwriteRefs.length > 0) {
    console.error(
      `\nWarning: ${overwriteRefs.length} secret(s) already exist in store:`
    );
    for (const ref of overwriteRefs) {
      console.error(`  ${ref}`);
    }
    const overwrite = await promptConfirm('Overwrite existing secrets? (y/N): ');
    if (!overwrite) {
      // Filter out existing
      const existing = new Set(overwriteRefs);
      const filtered = toImport.filter((c) => !existing.has(c.secretRef));
      if (filtered.length === 0) {
        console.error('No new secrets to import.');
        return;
      }
      toImport.length = 0;
      toImport.push(...filtered);
      console.error(`Importing ${toImport.length} new secret(s), skipping existing.`);
    }
  }

  // Import using setMany if available, otherwise sequential set()
  const entries: [string, string][] = toImport.map((c) => [
    c.secretRef,
    c.entry.value,
  ]);

  if (store.setMany) {
    await store.setMany(entries, passphrase);
  } else {
    for (const [ref, value] of entries) {
      await store.set(ref, value, passphrase);
    }
  }

  console.error(`\nImported ${toImport.length} secret(s) into store.`);

  // Step 9: Cleanup source files
  if (!noCleanup) {
    await cleanupFiles(cwd, found, secrets);
  }

  // Step 10: Config suggestions for unmatched secrets
  const unmatched = toImport.filter((c) => !c.matchedService);
  if (unmatched.length > 0) {
    console.error(
      `\nNote: ${unmatched.length} imported secret(s) don't have matching services in keyhole.yaml:`
    );
    for (const c of unmatched) {
      console.error(`  - ${c.secretRef}`);
    }
    console.error(
      '\nThese secrets are stored securely but won\'t be auto-injected until'
    );
    console.error('you configure the corresponding service in keyhole.yaml.');
  }

  // Step 11: .gitignore check
  checkGitignore(cwd, found);
}

/**
 * Prompt the user to clean up each source file.
 */
async function cleanupFiles(
  cwd: string,
  files: SourceFile[],
  secrets: SecretCandidate[]
): Promise<void> {
  // Group secrets by file
  const byFile = new Map<string, SecretCandidate[]>();
  for (const c of secrets) {
    const group = byFile.get(c.entry.file) || [];
    group.push(c);
    byFile.set(c.entry.file, group);
  }

  for (const sf of files) {
    const fileSecrets = byFile.get(sf.filename);
    if (!fileSecrets || fileSecrets.length === 0) continue;

    console.error(`\nClean up ${sf.filename}?`);
    console.error('  [R] Replace values with placeholders (KEYHOLE_MANAGED)');
    console.error('  [D] Delete secret lines entirely');
    console.error('  [S] Skip — leave file unchanged');

    const choice = await promptChoice('Choice (R/D/S): ', ['r', 'd', 's']);
    if (choice === 's') continue;

    const filePath = path.join(cwd, sf.filename);

    // Create backup before modifying
    createBackup(filePath);

    if (sf.format === 'env') {
      cleanupEnvFile(filePath, fileSecrets, choice);
    } else {
      cleanupJsonFile(filePath, fileSecrets, choice);
    }

    console.error(`  ${sf.filename} updated (backup saved as ${sf.filename}.bak)`);
  }
}

/**
 * Prompt for a single-character choice.
 */
async function promptChoice(
  prompt: string,
  validChoices: string[]
): Promise<string> {
  const readline = await import('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    const ask = () => {
      rl.question(prompt, (answer) => {
        const lower = answer.trim().toLowerCase();
        if (validChoices.includes(lower)) {
          rl.close();
          resolve(lower);
        } else {
          ask();
        }
      });
    };
    ask();
  });
}

/**
 * Create a backup of a file before modifying it.
 */
function createBackup(filePath: string): void {
  const bakPath = filePath + '.bak';
  if (fs.existsSync(bakPath)) {
    // Append timestamp to avoid overwriting existing backup
    const timestamp = Math.floor(Date.now() / 1000);
    fs.copyFileSync(filePath, `${bakPath}.${timestamp}`);
  } else {
    fs.copyFileSync(filePath, bakPath);
  }
}

/**
 * Clean up an .env-style file by replacing or deleting secret lines.
 */
function cleanupEnvFile(
  filePath: string,
  secrets: SecretCandidate[],
  mode: string
): void {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const secretKeys = new Set(secrets.map((c) => c.entry.key));

  const output: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments — always preserve
    if (!trimmed || trimmed.startsWith('#')) {
      output.push(line);
      continue;
    }

    // Parse the key from this line
    let parseLine = trimmed;
    if (parseLine.startsWith('export ')) {
      parseLine = parseLine.substring(7).trim();
    }
    const eqIdx = parseLine.indexOf('=');
    if (eqIdx === -1) {
      output.push(line);
      continue;
    }

    const key = parseLine.substring(0, eqIdx).trim();

    if (!secretKeys.has(key)) {
      output.push(line);
      continue;
    }

    if (mode === 'd') {
      // Delete: skip this line entirely
      continue;
    }

    // Replace: preserve quoting style and export prefix
    const secret = secrets.find((c) => c.entry.key === key);
    if (!secret) {
      output.push(line);
      continue;
    }

    const prefix = secret.entry.hasExport ? 'export ' : '';
    const placeholder = 'KEYHOLE_MANAGED';

    let replacement: string;
    switch (secret.entry.quoteStyle) {
      case 'double':
        replacement = `${prefix}${key}="${placeholder}"`;
        break;
      case 'single':
        replacement = `${prefix}${key}='${placeholder}'`;
        break;
      default:
        replacement = `${prefix}${key}=${placeholder}`;
    }

    output.push(replacement);
  }

  fs.writeFileSync(filePath, output.join('\n'));
}

/**
 * Clean up a JSON file by replacing or deleting secret values.
 */
function cleanupJsonFile(
  filePath: string,
  secrets: SecretCandidate[],
  mode: string
): void {
  const content = fs.readFileSync(filePath, 'utf-8');
  let parsed: any;
  try {
    parsed = JSON.parse(content);
  } catch {
    return;
  }

  const secretPaths = new Set(secrets.map((c) => c.entry.key));

  for (const keyPath of secretPaths) {
    const parts = keyPath.split('.');
    let obj = parsed;

    // Navigate to the parent object
    for (let i = 0; i < parts.length - 1; i++) {
      if (obj && typeof obj === 'object' && parts[i] in obj) {
        obj = obj[parts[i]];
      } else {
        obj = null;
        break;
      }
    }

    if (!obj || typeof obj !== 'object') continue;

    const lastKey = parts[parts.length - 1];
    if (mode === 'd') {
      delete obj[lastKey];
    } else {
      obj[lastKey] = 'KEYHOLE_MANAGED';
    }
  }

  fs.writeFileSync(filePath, JSON.stringify(parsed, null, 2) + '\n');
}

/**
 * Warn if secret files are not in .gitignore.
 */
function checkGitignore(cwd: string, files: SourceFile[]): void {
  const gitignorePath = path.join(cwd, '.gitignore');
  if (!fs.existsSync(gitignorePath)) return;

  const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
  const lines = gitignore
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  for (const sf of files) {
    // Only warn for .env-style files (JSON config files are typically not gitignored)
    if (sf.format !== 'env') continue;

    const isIgnored = lines.some((pattern) => {
      if (pattern === sf.filename) return true;
      if (pattern === '.env*' || pattern === '.env.*') return true;
      if (pattern.endsWith('/') && sf.filename.startsWith(pattern)) return true;
      return false;
    });

    if (!isIgnored) {
      console.error(
        `\nWarning: ${sf.filename} is NOT in .gitignore — consider adding it to prevent accidental commits.`
      );
    }
  }
}
