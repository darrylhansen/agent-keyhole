/**
 * Mock keychain for cross-platform testing.
 *
 * Intercepts `child_process.execFileSync` calls that target OS keychain
 * commands (`security` on macOS, `secret-tool` on Linux) and routes them
 * to an in-memory Map.
 *
 * Also mocks `os.platform()` so tests can simulate macOS/Linux regardless
 * of the real host OS.
 */

import childProcess from 'child_process';
import os from 'os';
import { mock } from 'node:test';

export interface ExecFileOpts {
  input?: string | Buffer;
  encoding?: string;
  stdio?: any;
  maxBuffer?: number;
  [key: string]: any;
}

export interface MockKeychainOptions {
  platform?: 'darwin' | 'linux';
  secrets?: Record<string, string>;
}

export interface MockKeychainResult {
  /** In-memory key-value store backing the mock */
  store: Map<string, string>;
  /** Restore original functions (call in afterEach) */
  restore: () => void;
}

/**
 * Install the mock keychain. Returns `store` for test inspection and
 * `restore()` for cleanup.
 */
export function installMockKeychain(
  options?: MockKeychainOptions
): MockKeychainResult {
  const platform = options?.platform || 'darwin';
  const store = new Map<string, string>(
    Object.entries(options?.secrets || {})
  );

  // Save originals
  const originalExecFileSync = childProcess.execFileSync;
  const originalPlatform = os.platform;

  // Mock os.platform()
  const platformMock = mock.fn(() => platform);
  (os as any).platform = platformMock;

  // Mock execFileSync — captures opts.input for stdin-piped secrets
  const execMock = mock.fn(
    (cmd: string, args: readonly string[], opts?: ExecFileOpts): Buffer => {
      if (platform === 'darwin' && cmd === 'security') {
        return handleMacOSKeychain(store, args, opts);
      }
      if (platform === 'linux' && cmd === 'secret-tool') {
        return handleLinuxKeychain(store, args, opts);
      }
      // Not a keychain call — call original
      return originalExecFileSync(cmd, args as string[], opts as any) as unknown as Buffer;
    }
  );
  (childProcess as any).execFileSync = execMock;

  return {
    store,
    restore() {
      (childProcess as any).execFileSync = originalExecFileSync;
      (os as any).platform = originalPlatform;
    },
  };
}

// ─── macOS: `security find-generic-password` / `security add-generic-password` ───

function handleMacOSKeychain(
  store: Map<string, string>,
  args: readonly string[],
  opts?: ExecFileOpts
): Buffer {
  const argsArr = [...args];

  if (argsArr[0] === 'find-generic-password') {
    const accountIdx = argsArr.indexOf('-a');
    const serviceIdx = argsArr.indexOf('-s');
    const account = accountIdx >= 0 ? argsArr[accountIdx + 1] : '';
    const service = serviceIdx >= 0 ? argsArr[serviceIdx + 1] : '';
    const key = `${service}:${account}`;

    if (argsArr.includes('-w')) {
      // Return password only
      const value = store.get(key);
      if (value === undefined) {
        throw Object.assign(
          new Error(`security: SecItemNotFound`),
          { status: 44, stderr: Buffer.from('security: SecItemNotFound') }
        );
      }
      return Buffer.from(value + '\n');
    }
    // Not -w: would return all fields, but tests always use -w
    return Buffer.from('');
  }

  if (argsArr[0] === 'add-generic-password') {
    const accountIdx = argsArr.indexOf('-a');
    const serviceIdx = argsArr.indexOf('-s');
    const account = accountIdx >= 0 ? argsArr[accountIdx + 1] : '';
    const service = serviceIdx >= 0 ? argsArr[serviceIdx + 1] : '';
    const key = `${service}:${account}`;

    // Real KeychainStore passes secret via opts.input (stdin), not as -w value arg.
    // The -w flag is present but has no value — the secret is piped to avoid ps exposure.
    let password = '';
    if (opts?.input) {
      password = typeof opts.input === 'string'
        ? opts.input
        : opts.input.toString('utf-8');
    } else {
      // Fallback: check if -w has a value arg (for simpler test setups)
      const passwordIdx = argsArr.indexOf('-w');
      if (passwordIdx >= 0) {
        const nextArg = argsArr[passwordIdx + 1];
        // Only treat as password if it's not another flag
        if (nextArg && !nextArg.startsWith('-')) {
          password = nextArg;
        }
      }
    }

    store.set(key, password);
    return Buffer.from('');
  }

  if (argsArr[0] === 'delete-generic-password') {
    const accountIdx = argsArr.indexOf('-a');
    const serviceIdx = argsArr.indexOf('-s');
    const account = accountIdx >= 0 ? argsArr[accountIdx + 1] : '';
    const service = serviceIdx >= 0 ? argsArr[serviceIdx + 1] : '';
    const key = `${service}:${account}`;
    store.delete(key);
    return Buffer.from('');
  }

  if (argsArr[0] === 'dump-keychain') {
    // Return mock dump output for list()
    let output = '';
    for (const [key, _value] of store) {
      const [svc, acct] = key.split(':');
      output += `    "svce"<blob>="${svc}"\n`;
      output += `    "acct"<blob>="${acct}"\n`;
    }
    return Buffer.from(output);
  }

  return Buffer.from('');
}

// ─── Linux: `secret-tool lookup` / `secret-tool store` / `secret-tool clear` ───

function handleLinuxKeychain(
  store: Map<string, string>,
  args: readonly string[],
  opts?: ExecFileOpts
): Buffer {
  const argsArr = [...args];

  if (argsArr[0] === 'lookup') {
    // secret-tool lookup attribute value attribute value ...
    const key = extractSecretToolKey(argsArr.slice(1));
    const value = store.get(key);
    if (value === undefined) {
      throw Object.assign(
        new Error(`No matching secret found`),
        { status: 1, stderr: Buffer.from('No matching secret found') }
      );
    }
    return Buffer.from(value);
  }

  if (argsArr[0] === 'store') {
    // secret-tool store --label=<label> attribute value attribute value ...
    const labelIdx = argsArr.findIndex((a) => a.startsWith('--label'));
    const attrStart = labelIdx >= 0 ? labelIdx + 1 : 1;
    const key = extractSecretToolKey(argsArr.slice(attrStart));

    // Real KeychainStore passes secret via opts.input (stdin)
    let secret = '';
    if (opts?.input) {
      secret = typeof opts.input === 'string'
        ? opts.input
        : opts.input.toString('utf-8');
    }

    store.set(key, secret);
    return Buffer.from('');
  }

  if (argsArr[0] === 'clear') {
    // secret-tool clear attribute value attribute value ...
    const key = extractSecretToolKey(argsArr.slice(1));
    store.delete(key);
    return Buffer.from('');
  }

  if (argsArr[0] === 'search') {
    // secret-tool search --all service <name>
    let output = '';
    for (const [key, _value] of store) {
      // Parse sorted pairs back out for attribute listing
      const pairs = key.split(':');
      for (const pair of pairs) {
        const [attr, val] = pair.split('=');
        output += `attribute.${attr} = ${val}\n`;
      }
      output += '\n';
    }
    return Buffer.from(output);
  }

  return Buffer.from('');
}

/**
 * Build a canonical key from attribute pairs.
 * Sorts pairs alphabetically so lookups match stores regardless of
 * argument ordering in the source code.
 */
function extractSecretToolKey(pairs: string[]): string {
  const parts: string[] = [];
  for (let i = 0; i < pairs.length; i += 2) {
    if (i + 1 < pairs.length) {
      parts.push(`${pairs[i]}=${pairs[i + 1]}`);
    }
  }
  parts.sort();
  return parts.join(':');
}
