# Agent-Keyhole v1.0.0 – Complete Technical Specification

**Tagline:** A trust boundary for LLM agents. Your agent never holds your real credentials.

**Package name:** `agent-keyhole`  
**License:** MIT  
**Runtime dependency:** `js-yaml` (YAML config parsing)  
**Node.js minimum:** 18.x (required for native `fetch` / `globalThis.fetch` support)  
**Platforms:** macOS, Linux  
**Install:** `npm install agent-keyhole` (project-local dependency)

**Revision History:**
- v0.1: Initial spec

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Architecture Overview](#2-architecture-overview)
3. [Secret Store](#3-secret-store)
4. [Sidecar Process](#4-sidecar-process)
5. [IPC Transport](#5-ipc-transport)
6. [HTTP Interceptor](#6-http-interceptor)
7. [Request Builder](#7-request-builder)
8. [Response Masker](#8-response-masker)
9. [Client Factory](#9-client-factory)
10. [Safe Environment Generator](#10-safe-environment-generator)
11. [Configuration Schema](#11-configuration-schema)
12. [CLI](#12-cli)
13. [Public API](#13-public-api)
14. [Multi-Agent Support](#14-multi-agent-support)
15. [Moltbot Integration](#15-moltbot-integration)
16. [Error Handling](#16-error-handling)
17. [Audit Logging](#17-audit-logging)
18. [Project Structure](#18-project-structure)
19. [Build & Distribution](#19-build--distribution)
20. [Testing Strategy](#20-testing-strategy)
21. [Security Considerations](#21-security-considerations)
22. [Future Scope (Not v1)](#22-future-scope-not-v1)
23. [Build Phases](#23-build-phases)

---

## 1. Threat Model

### 1.1 What Keyhole Protects Against

The agent process (LLM-driven, potentially prompt-injectable) **never holds real secret 
material**. Even if the agent is:

- **Prompt-injected** into dumping `process.env`, it only sees dummy placeholder values.
- **Jailbroken** into executing arbitrary code, it cannot read the sidecar's memory 
  (separate OS process).
- **Instructed** to exfiltrate via HTTP, any response containing credential material is 
  redacted before the agent sees it.
- **Manipulated** into reading filesystem, there are no secret files to find (secrets live 
  in OS keychain or encrypted vault and sidecar RAM only).

### 1.2 What Keyhole Does NOT Protect Against

- **Authorized misuse:** A compromised agent can still *use* the sidecar to make API calls 
  it shouldn't. It has the *ability* to call configured services, just not the *credentials*. 
  Mitigation: the Policy Engine (v1.5) adds method/path allow-deny rules.
- **Network exfiltration of non-secret data:** The agent can still send API response data to 
  a third party if it has network access. Keyhole is a credential firewall, not a network 
  firewall.
- **Compromise of the host machine:** If an attacker has root/admin access to the machine, 
  they can read any process memory. This is outside Keyhole's threat model.

### 1.3 Security Hierarchy of Integration Modes

| Mode | What agent sees | Isolation level | Use case |
|---|---|---|---|
| `createClient()` (IPC direct) | Nothing – no URLs, no keys, no domains | **Strongest** | New skills written for Keyhole |
| HTTP interceptor (`autoPatch`) | Dummy keys in env, doesn't know about proxy | **Strong** | Legacy skills, transparent adoption |
| Either mode + response masking | Redacted responses, no credential leakage | **Applied to both** | Always on |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  AGENT PROCESS (untrusted)                                   │
│                                                              │
│  process.env.GITHUB_TOKEN = "KEYHOLE_MANAGED"               │
│  process.env.OPENAI_API_KEY = "sk-keyhole-000..."           │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  HTTP Interceptor                                       │ │
│  │  Patches: http.request, https.request, globalThis.fetch │ │
│  │  Matches outbound domain → routes to sidecar via IPC    │ │
│  │  Non-matching domains → pass through unmodified         │ │
│  └───────────────────────┬────────────────────────────────┘ │
│                          │                                   │
│  ┌───────────────────────┴────────────────────────────────┐ │
│  │  Keyhole Client (optional, for new skills)              │ │
│  │  fetch-compatible function, routes directly over IPC    │ │
│  └───────────────────────┬────────────────────────────────┘ │
└──────────────────────────┼──────────────────────────────────┘
                           │ 
                    Unix Domain Socket
                    + OTT authentication
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  KEYHOLE SIDECAR PROCESS (trusted)                           │
│                                                              │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │ Config       │  │ Secret Store  │  │ OTT Registry     │ │
│  │ (from YAML,  │  │ (OS keychain  │  │ (validates       │ │
│  │  immutable   │  │  or encrypted │  │  every request)  │ │
│  │  after boot) │  │  vault → RAM) │  │                  │ │
│  └──────┬───────┘  └──────┬────────┘  └────────┬─────────┘ │
│         │                 │                     │           │
│  ┌──────▼─────────────────▼─────────────────────▼─────────┐ │
│  │  Request Builder                                        │ │
│  │  - Validates service name + agent access                │ │
│  │  - Resolves base URL from config                        │ │
│  │  - Strips all agent-provided auth                       │ │
│  │  - Injects real credentials from secret store           │ │
│  │  - Adds service-specific headers from config            │ │
│  │  - Handles redirects with domain validation             │ │
│  └──────────────────────┬─────────────────────────────────┘ │
│                         │                                    │
│                    Outbound HTTP/HTTPS                        │
│                    to real API                                │
│                         │                                    │
│  ┌──────────────────────▼─────────────────────────────────┐ │
│  │  Response Masker                                        │ │
│  │  L1: Header scrub (always on)                           │ │
│  │  L2: Known-secret body scan (always on)                 │ │
│  │  L3: Pattern-based redaction (per-service config)       │ │
│  │  L4: JSON path redaction (per-service config)           │ │
│  │  Streaming: sliding window buffer at chunk boundaries   │ │
│  └──────────────────────┬─────────────────────────────────┘ │
│                         │                                    │
│  ┌──────────────────────▼─────────────────────────────────┐ │
│  │  Audit Logger + Alerting                                │ │
│  │  - Logs all proxied calls (no secret material)          │ │
│  │  - Flags redaction events                               │ │
│  │  - Webhook alerts for VPS boot failures                 │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Secret Store

### 3.1 Interface

```typescript
interface SecretStore {
  /** Retrieve a secret by reference name */
  get(ref: string): Promise<string>;
  
  /** Store a secret */
  set(ref: string, value: string): Promise<void>;
  
  /** Delete a secret */
  delete(ref: string): Promise<void>;
  
  /** List all stored secret reference names */
  list(): Promise<string[]>;
  
  /** Check if a secret exists without retrieving it */
  has(ref: string): Promise<boolean>;
}
```

### 3.2 Keychain Implementation (Desktop Default)

The default `SecretStore` uses the operating system's native credential storage via 
shell-outs. No native Node.js dependencies required.

**Service name for all keychain entries:** `agent-keyhole`  
**Account name:** The `secret_ref` value from config (e.g., `github-token`, `openai-api-key`)

#### macOS (Keychain Access)

```
# Get
security find-generic-password -s agent-keyhole -a <ref> -w

# Set (delete first to avoid "already exists" error)
security delete-generic-password -s agent-keyhole -a <ref> 2>/dev/null
security add-generic-password -s agent-keyhole -a <ref> -w <value> \
  -T /usr/bin/security -T <node-binary-path>

# Delete
security delete-generic-password -s agent-keyhole -a <ref>

# List (parse output for agent-keyhole entries)
security dump-keychain | grep -A4 "agent-keyhole"
```

**Security notes for macOS:**

The CLI pipes secrets via `stdin` to avoid exposure in `ps` output:

```typescript
// Preferred: pipe secret via stdin to avoid ps exposure
const child = execFileSync('security', [
  'add-generic-password', '-s', 'agent-keyhole', '-a', ref, '-w',
  '-T', '/usr/bin/security',   // Allow security CLI to read without prompt
  '-T', process.execPath       // Allow the actual Node binary to read without prompt
], { input: value });
```

**macOS GUI Prompt Prevention:** The `-T` flags grant both the `security` CLI and the 
current Node binary access to the keychain entry without triggering a macOS access-control 
GUI popup. Using `process.execPath` (rather than `which node`) is critical because version
managers like `nvm` and `volta` may resolve to different paths. Without this, the first
read from the sidecar process may block on an invisible dialog.

#### Linux (libsecret / secret-tool)

```
# Get
secret-tool lookup service agent-keyhole account <ref>

# Set
echo -n <value> | secret-tool store --label="agent-keyhole:<ref>" \
  service agent-keyhole account <ref>

# Delete
secret-tool clear service agent-keyhole account <ref>

# List
secret-tool search --all service agent-keyhole
```

**Fallback:** If `secret-tool` is not installed (headless servers), the store should detect 
this at boot and direct the user to either install `secret-tool` or use the encrypted vault 
store: `npx keyhole vault create`.

### 3.3 Encrypted Vault Implementation (VPS / Headless)

For persistent headless environments (VPS, dedicated servers) where there is no OS keychain
(no D-Bus session, no GUI) but secrets need to survive reboots without being stored in
plaintext, the vault store provides encrypted-at-rest secret storage.

**File:** `.keyhole.vault` (binary, in project root or configurable path)  
**Encryption:** AES-256-GCM (authenticated encryption) via Node.js `crypto` module  
**Key derivation:** `crypto.scryptSync` from a master passphrase  
**Zero additional dependencies**

#### Vault File Format

```
[16 bytes: salt]                    – Random, generated on vault creation
[12 bytes: IV]                      – Random per write, regenerated on every save
[16 bytes: GCM auth tag]            – Integrity verification
[N bytes: ciphertext]               – AES-256-GCM encrypted JSON payload
```

The decrypted payload is a JSON object:

```json
{
  "version": 1,
  "created_at": "2025-01-15T12:00:00Z",
  "secrets": {
    "github-token": "ghp_real_secret_value",
    "openai-api-key": "sk-real_secret_value"
  }
}
```

#### Implementation

```typescript
// src/store/vault.ts

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';

const scrypt = promisify(crypto.scrypt);

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
  
  /** Derive AES-256 key from passphrase using asynchronous scrypt */
  private async deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
    return (await scrypt(passphrase, salt, SCRYPT_KEYLEN, {
      N: SCRYPT_COST,
      r: SCRYPT_BLOCK,
      p: SCRYPT_PARALLEL
    })) as Buffer;
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
    const authTag = raw.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = raw.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
    
    const key = await this.deriveKey(passphrase, salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted: string;
    try {
      decrypted = decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
    } catch {
      throw new Error('Invalid passphrase or corrupted vault');
    }
    
    const payload = JSON.parse(decrypted) as VaultPayload;
    this.secrets = new Map(Object.entries(payload.secrets));
  }
  
  /** Save current state to encrypted vault file using atomic write */
  private async saveVault(passphrase: string, payload?: VaultPayload): Promise<void> {
    const data = payload || {
      version: 1,
      created_at: new Date().toISOString(),
      secrets: Object.fromEntries(this.secrets!)
    };
    
    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = await this.deriveKey(passphrase, salt);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = JSON.stringify(data);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
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
  
  async set(ref: string, value: string, passphrase: string): Promise<void> {
    if (!this.secrets) await this.unlock(passphrase);
    this.secrets!.set(ref, value);
    await this.saveVault(passphrase);
  }
  
  async delete(ref: string, passphrase: string): Promise<void> {
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
  
  get isLocked(): boolean {
    return this.secrets === null;
  }
}
```

#### Passphrase Delivery

The master passphrase is provided to the sidecar at boot time via the **IPC bootstrap 
message**. The passphrase is held in memory only long enough to decrypt the vault, then 
the variable is overwritten (best-effort memory clearing).

```typescript
// Parent sends passphrase via IPC (never via env var, never via CLI arg)
childProcess.send({
  type: 'bootstrap',
  ott: '<64-char hex string>',
  config: { /* ... */ },
  vaultPassphrase: passphrase
});

// Sidecar receives, decrypts vault, then clears:
// passphrase = '\0'.repeat(passphrase.length);
```

**⚠ Important: V8 string immutability limitation.** JavaScript strings are immutable in V8.
The reassignment `passphrase = '\0'.repeat(passphrase.length)` overwrites the *variable 
binding* but does NOT erase the original string from V8's managed heap. The original string
data remains in memory until the garbage collector reclaims it, and there is no way to force
immediate collection or zeroing in standard Node.js. This is a best-effort mitigation that:
- Removes the only reachable reference, making GC *eligible* to reclaim the memory
- Reduces the window of exposure compared to keeping the reference alive
- Is the best available option without native addons or `Buffer`-based passphrase handling

For higher-security environments, consider passing the passphrase as a `Buffer` and using
`buffer.fill(0)` after use, which *does* zero the underlying memory. However, this requires
all consumers (scrypt, etc.) to accept `Buffer` input. This is tracked as a v1.5 hardening
item.

**Why not environment variables?** Even on the sidecar process, env vars are readable via 
`/proc/PID/environ` on Linux for the lifetime of the process. `delete process.env.VAR` 
removes it from Node's view but does NOT remove it from `/proc`. The IPC channel is a 
private file descriptor between parent and child – it is not inspectable via `/proc` or 
any standard process inspection tool.

### 3.4 Store Selection Logic

```typescript
async function createStore(options?: { 
  store?: 'keychain' | 'vault';
  vaultPath?: string;
}): Promise<SecretStore> {
  if (options?.store === 'vault') return new VaultStore(options.vaultPath);
  if (options?.store === 'keychain') return new KeychainStore();
  
  // Auto-detect: keychain → vault
  try {
    await testKeychainAccess();
    return new KeychainStore();
  } catch {
    const vaultPath = options?.vaultPath || '.keyhole.vault';
    if (fs.existsSync(vaultPath)) {
      console.warn('[keyhole] OS keychain not available, using encrypted vault');
      return new VaultStore(vaultPath);
    }
    throw new Error(
      'No secret store available. Either:\n' +
      '  - Run on a system with an OS keychain (macOS Keychain, Linux secret-tool)\n' +
      '  - Create an encrypted vault: npx keyhole vault create'
    );
  }
}
```

**Store selection priority:**
1. **OS Keychain** (default) – macOS, Linux desktop
2. **Encrypted Vault** – VPS, headless servers, any environment with `.keyhole.vault` present

**There is no env var store.** Putting secrets in environment variables – even on the sidecar
process – contradicts Keyhole's core security premise. Env vars are readable via 
`/proc/PID/environ` on Linux and visible to process inspection tools. If your environment
cannot support either keychain or vault, Keyhole is not the right tool – use a dedicated
secrets manager like HashiCorp Vault or AWS Secrets Manager directly.

---

## 4. Sidecar Process

### 4.1 Lifecycle

The sidecar runs as a child process of the host application. It is spawned by the 
`createKeyhole()` factory and killed by `keyhole.shutdown()` or when the parent process 
exits.

#### Boot Sequence

```
1. Parent calls createKeyhole()
2. Parent loads and validates keyhole.yaml
3. Parent generates OTT (32 bytes, crypto.randomBytes, hex-encoded = 64 chars)
4. Parent spawns child process:
   - Entry point: src/sidecar/process.ts
   - Communication: stdio IPC channel (Node.js built-in)
   - Environment: minimal (no agent env vars, only KEYHOLE_STORE=keychain|vault)
5. Parent sends bootstrap message over IPC:
   {
     type: 'bootstrap',
     ott: '<64-char hex string>',
     config: { /* parsed and validated config object */ },
     vaultPassphrase?: '<passphrase>'  // Only for vault store, cleared after use
   }
6. Sidecar receives bootstrap message
7. Sidecar creates SecretStore instance
8. Sidecar attempts to resolve ALL secrets referenced in config:

   a. KEYCHAIN store:
      - If any secret is missing, send error and exit
      - This validates config completeness at boot, not at first request
   
   b. VAULT store:
      - If passphrase is provided → unlock vault, resolve secrets
      - If passphrase is NOT provided → enter PENDING_UNLOCK state:
        - Sidecar starts the IPC socket server
        - Health endpoint returns { state: 'pending_unlock' }
        - All proxy requests are rejected with { error: 'Vault is locked' }
        - If alerting.webhook_url is configured, send alert (see 4.3)
        - Sidecar waits for an 'unlock' IPC message from the parent:
          { type: 'unlock', passphrase: '<passphrase>' }
        - On successful unlock → resolve secrets, transition to READY state
        - On failed unlock → remain in PENDING_UNLOCK, log error

9. Sidecar creates Unix Domain Socket
   - Socket path: <socket_dir>/keyhole-<random>.sock
     where <socket_dir> defaults to os.tmpdir(), overridable via config
   - <random> = 16 bytes hex from crypto.randomBytes
   - Socket file permissions: 0o600 (owner read/write only)
   - Permissions are set synchronously BEFORE the ready signal is sent
10. Sidecar stores OTT in private memory
11. Sidecar sends ready message over IPC:
    {
      type: 'ready',
      socketPath: '/tmp/keyhole-abc123.sock',
      state: 'ready' | 'pending_unlock'
    }
12. Parent receives ready message
13. Parent stores socketPath for client/interceptor use
14. Parent returns keyhole instance to caller
    - If state is 'pending_unlock', the keyhole instance exposes an unlock() method
```

#### Shutdown Sequence

```
1. Parent calls keyhole.shutdown() (or parent process exits)
2. Parent sends { type: 'shutdown' } over IPC
3. Sidecar closes Unix socket
4. Sidecar removes socket file from filesystem
5. Sidecar zeroes secret memory (best-effort: overwrite Buffer contents)
6. Sidecar exits with code 0
7. If sidecar doesn't exit within 5 seconds, parent sends SIGKILL
```

#### Crash Recovery

```
- If sidecar crashes, parent detects via 'exit' event on child process
- Parent emits 'error' event on keyhole instance
- All pending requests receive an error response
- If autoRestart is enabled:
  - New OTT is generated, new socket is created
  - IPCClient.updateConnection() is called with new socket path + OTT
  - Pending requests from the crashed session are rejected
  - Interceptor continues to work (references IPCClient, which is updated)
  - 'restarted' event emitted on keyhole instance
```

**Implementation note:** The crash handler must be implemented as a **named function** (not
`arguments.callee`, which is forbidden in strict mode and ES modules). The spawn logic
should be structured as:

```typescript
// src/client/spawn.ts (sketch)

async function spawnSidecar(config: ParsedConfig, options: KeyholeOptions): Promise<SidecarHandle> {
  const startSidecar = async (): Promise<SidecarHandle> => {
    const ott = crypto.randomBytes(32).toString('hex');
    const child = fork(sidecarEntryPoint, [], { /* ... */ });
    
    child.on('exit', (code, signal) => {
      if (options.autoRestart && code !== 0) {
        // Named function reference — safe in strict mode and ES modules
        startSidecar().then(handle => {
          ipcClient.updateConnection(handle.socketPath, handle.ott);
          keyhole.emit('restarted');
        }).catch(err => {
          keyhole.emit('error', err);
        });
      }
    });
    
    // ... bootstrap, wait for ready
    return { child, socketPath, ott };
  };
  
  return startSidecar();
}
```

### 4.2 Process Entry Point

```typescript
// src/sidecar/process.ts
// This file runs in the CHILD process

type SidecarState = 'booting' | 'pending_unlock' | 'ready' | 'shutting_down';

let state: SidecarState = 'booting';
let store: SecretStore;
let secrets: Map<string, string>;
let builder: RequestBuilder;
let masker: ResponseMasker;
let config: ParsedConfig;

process.on('message', async (msg) => {
  if (msg.type === 'bootstrap') {
    await bootstrap(msg.ott, msg.config, msg.vaultPassphrase);
  }
  if (msg.type === 'unlock') {
    await handleUnlock(msg.passphrase);
  }
  if (msg.type === 'shutdown') {
    await shutdown();
    process.exit(0);
  }
});

async function bootstrap(ott: string, cfg: ParsedConfig, passphrase?: string) {
  config = cfg;
  
  // 1. Create secret store
  store = await createStore({ 
    store: process.env.KEYHOLE_STORE as any,
    vaultPath: cfg.vaultPath 
  });
  
  // 2. Attempt to resolve secrets
  if (store instanceof VaultStore) {
    if (passphrase) {
      try {
        await store.unlock(passphrase);
        // Best-effort clearing: overwrites the variable binding but does NOT erase the
        // original string from V8's heap (strings are immutable in V8). The original
        // remains until GC reclaims it. See section 3.3 "Passphrase Delivery" for details.
        passphrase = '\0'.repeat(passphrase.length);
      } catch (err) {
        process.send({ type: 'error', message: `Vault unlock failed: ${err.message}` });
        process.exit(1);
      }
      await resolveSecrets();
    } else {
      // No passphrase – enter PENDING_UNLOCK state
      state = 'pending_unlock';
      const socketPath = await startIPCServer(ott, null, null, logger, config.socket_dir);
      process.send({ type: 'ready', socketPath, state: 'pending_unlock' });
      await sendBootAlert(config);
      return;
    }
  } else {
    await resolveSecrets();
  }
  
  // 3. Create request builder and response masker
  builder = new RequestBuilder(config, secrets);
  masker = new ResponseMasker(config, secrets);
  
  // 4. Start IPC server on unix socket
  const socketPath = await startIPCServer(ott, builder, masker, logger, config.socket_dir);
  
  // 5. Signal ready
  state = 'ready';
  process.send({ type: 'ready', socketPath, state: 'ready' });
}

async function resolveSecrets() {
  secrets = new Map<string, string>();
  for (const [name, service] of Object.entries(config.services)) {
    try {
      const secret = await store.get(service.auth.secret_ref);
      secrets.set(service.auth.secret_ref, secret);
    } catch (err) {
      process.send({ 
        type: 'error', 
        message: `Missing secret for service "${name}": ${err.message}` 
      });
      process.exit(1);
    }
  }
}

async function handleUnlock(passphrase: string) {
  if (state !== 'pending_unlock') {
    process.send({ type: 'error', message: 'Sidecar is not in pending_unlock state' });
    return;
  }
  
  try {
    await (store as VaultStore).unlock(passphrase);
    // Best-effort clearing: see section 3.3 "Passphrase Delivery" for V8 limitations
    passphrase = '\0'.repeat(passphrase.length);
    
    await resolveSecrets();
    builder = new RequestBuilder(config, secrets);
    masker = new ResponseMasker(config, secrets);
    updateServerHandlers(builder, masker);
    
    state = 'ready';
    process.send({ type: 'unlocked', state: 'ready' });
  } catch (err) {
    process.send({ type: 'error', message: `Vault unlock failed: ${err.message}` });
  }
}
```

### 4.3 Boot Alerting (VPS / Headless)

When the sidecar enters `PENDING_UNLOCK` state (vault exists but no passphrase was 
provided), it sends a webhook notification to alert the operator.

```typescript
// src/sidecar/alerting.ts

async function sendBootAlert(config: ParsedConfig): Promise<void> {
  if (!config.alerting?.webhook_url) return;
  
  const prefix = config.alerting.message_prefix || 'Agent-Keyhole';
  const hostname = os.hostname();
  const timestamp = new Date().toISOString();
  
  const payload = {
    content: `⚠️ **${prefix}** is locked and waiting for vault passphrase.\n` +
             `Host: \`${hostname}\`\n` +
             `Time: ${timestamp}\n` +
             `Action required: provide vault passphrase to unlock the sidecar.`
  };
  
  try {
    await fetch(config.alerting.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error(`[keyhole] Failed to send boot alert: ${err.message}`);
  }
}
```

**Alert triggers:**
- Sidecar boots with vault store but no passphrase → `PENDING_UNLOCK` → alert sent
- Sidecar boots but all secret resolution fails → alert sent before exit

**Alert does NOT fire when:**
- Sidecar boots successfully (state = `ready`)
- Sidecar is shut down intentionally
- Individual request failures (those are audit log events)

---

## 5. IPC Transport

### 5.1 Protocol

Communication between the agent-side client/interceptor and the sidecar uses a simple 
JSON-over-socket protocol with length-prefix framing.

#### Message Framing

Each message is prefixed with a 4-byte big-endian unsigned integer indicating the length 
of the JSON payload in bytes.

```
[4 bytes: payload length][N bytes: JSON payload]
```

#### Request Message

```typescript
interface KeyholeRequest {
  id: string;           // UUID v4, for correlating responses
  ott: string;          // One-time token for authentication
  service: string;      // Service name from config (e.g., "github")
  method: string;       // HTTP method
  path: string;         // Path + query string
  headers: Record<string, string>;  // Agent-provided headers (will be filtered)
  body?: string;            // Text body (UTF-8, for JSON/text payloads)
  bodyBase64?: string;      // Binary body (Base64-encoded)
  bodyEncoding: 'utf8' | 'base64';  // Which body field contains the payload
  agent?: string;       // Agent identity (for multi-agent mode)
}
```

**Binary body handling:** The interceptor and `FakeClientRequest` detect binary content via
`Content-Type` header (anything not `text/*`, `application/json`, `application/xml`, 
`application/x-www-form-urlencoded`) or by checking if the body is a Buffer with non-text
bytes. Binary bodies are Base64-encoded for IPC transport (~33% overhead, acceptable for
local socket) with `bodyEncoding: 'base64'`. The sidecar decodes before forwarding upstream.

**Body size limit:** Maximum request body size is 10MB. Requests exceeding this limit are
rejected with a clear error. The limit is enforced client-side during `.write()` calls to 
prevent OOM before the sidecar even sees the message. Large file uploads are addressed in 
v1.5 via IPC streaming with backpressure.

#### Response Message

```typescript
interface KeyholeResponse {
  id: string;           // Matches request id
  status: number;       // HTTP status code from upstream
  headers: Record<string, string>;  // Scrubbed response headers
  body: string;         // Masked response body (UTF-8 text)
  bodyBase64?: string;  // Response body (Base64-encoded, for binary responses)
  bodyEncoding: 'utf8' | 'base64';
  error?: string;       // Keyhole-level error
  redacted?: boolean;   // True if any masking was applied
}
```

**Binary response handling:** If upstream returns a binary `Content-Type`, the response body
is Base64-encoded for IPC transport. Layer 2 and Layer 3 response masking are **skipped**
for binary responses (credential strings don't appear inside images/protobuf/etc.).
Layer 1 (header scrub) always applies.

#### Streaming Response Message

For large or streaming responses, the sidecar sends multiple messages:

```typescript
interface KeyholeStreamChunk {
  id: string;
  type: 'stream_start' | 'stream_chunk' | 'stream_end';
  status?: number;              // Only on stream_start
  headers?: Record<string, string>;  // Only on stream_start
  chunk?: string;               // Base64-encoded chunk data
  redacted?: boolean;
}
```

### 5.2 Socket Server Implementation

```typescript
// src/sidecar/ipc-server.ts

export async function startIPCServer(
  ott: string,
  builder: RequestBuilder | null,
  masker: ResponseMasker | null,
  logger: AuditLogger,
  socketDir?: string
): Promise<string> {
  const socketId = crypto.randomBytes(16).toString('hex');
  const dir = socketDir || os.tmpdir();
  const socketPath = path.join(dir, `keyhole-${socketId}.sock`);
  const MAX_IPC_MESSAGE_SIZE = (10 * 1024 * 1024) + (64 * 1024);

  const server = net.createServer((conn) => {
    let chunks: Buffer[] = [];
    let totalLength = 0;
    
    conn.on('data', (data) => {
      chunks.push(data);
      totalLength += data.length;
      
      // Process messages once we have enough data for a header
      while (totalLength >= 4) {
        // Peek at length prefix from the chunks without full concatenation
        const headerBuffer = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, 4);
        const payloadLength = headerBuffer.readUInt32BE(0);
        
        if (payloadLength > MAX_IPC_MESSAGE_SIZE) {
          logger.warn(`Rejected message: ${payloadLength} bytes – destroying connection`);
          conn.destroy();
          return;
        }
        
        if (totalLength < 4 + payloadLength) break; 
        
        // Only concat exactly what we need for the current message
        const fullBuffer = Buffer.concat(chunks);
        const payload = fullBuffer.subarray(4, 4 + payloadLength);
        
        // Reset state with remaining data
        const remaining = fullBuffer.subarray(4 + payloadLength);
        chunks = remaining.length > 0 ? [remaining] : [];
        totalLength = remaining.length;
        
        try {
          const request = JSON.parse(payload.toString('utf-8')) as KeyholeRequest;
          handleRequest(request, conn, ott, builder, masker, logger);
        } catch (parseErr) {
          logger.warn(`Malformed IPC JSON: ${parseErr.message}`);
          continue;
        }
      }
    });
  });

  return new Promise((resolve, reject) => {
    // Clean up zombie socket files from previous hard exits (SIGKILL, power loss)
    if (fs.existsSync(socketPath)) {
      const testConn = net.createConnection(socketPath);
      testConn.on('connect', () => {
        testConn.destroy();
        reject(new Error(`Keyhole socket already in use: ${socketPath}`));
        return;
      });
      testConn.on('error', () => {
        try { fs.unlinkSync(socketPath); } catch {}
        listenOnSocket();
      });
    } else {
      listenOnSocket();
    }
    
    function listenOnSocket() {
      server.listen(socketPath, () => {
        fs.chmodSync(socketPath, 0o600);
        resolve(socketPath);
      });
      server.on('error', reject);
    }
  });
}

async function handleRequest(
  request: KeyholeRequest,
  conn: net.Socket,
  ott: string,
  builder: RequestBuilder | null,
  masker: ResponseMasker | null,
  logger: AuditLogger
) {
  // Health check (works even in PENDING_UNLOCK)
  if (request.service === '__health__') {
    const state = builder ? 'ready' : 'pending_unlock';
    sendResponse(conn, {
      id: request.id,
      status: state === 'ready' ? 200 : 503,
      headers: {},
      body: JSON.stringify({ state, uptime: process.uptime() }),
      bodyEncoding: 'utf8',
      redacted: false
    });
    return;
  }

  // Validate OTT
  if (!crypto.timingSafeEqual(Buffer.from(request.ott), Buffer.from(ott))) {
    sendResponse(conn, {
      id: request.id, status: 403, headers: {}, body: '',
      bodyEncoding: 'utf8', error: 'Invalid authentication token'
    });
    logger.warn('Rejected request with invalid OTT');
    return;
  }

  // Check if sidecar is ready (vault might be locked)
  if (!builder || !masker) {
    sendResponse(conn, {
      id: request.id, status: 503, headers: {}, body: '',
      bodyEncoding: 'utf8', error: 'Vault is locked – passphrase required'
    });
    return;
  }

  // Build and send the real request (with redirect protection)
  try {
    const { url, options } = builder.build(request);
    const service = builder.getServiceConfig(request.service);
    const upstreamResponse = await fetchWithRedirectPolicy(
      url, options, service, builder.getSecrets(), builder
    );
    
    // Determine if response is binary
    const contentType = upstreamResponse.headers.get('content-type') || '';
    const rawBuffer = Buffer.from(await upstreamResponse.arrayBuffer());
    const isBinary = masker.isBinaryResponse(contentType, rawBuffer);
    
    const maskedHeaders = masker.scrubHeaders(
      Object.fromEntries(upstreamResponse.headers.entries())
    );
    
    let responseMsg: KeyholeResponse;
    
    if (isBinary) {
      responseMsg = {
        id: request.id,
        status: upstreamResponse.status,
        headers: maskedHeaders,
        body: '',
        bodyBase64: rawBuffer.toString('base64'),
        bodyEncoding: 'base64',
        redacted: false
      };
    } else {
      const rawBody = rawBuffer.toString('utf-8');
      const { body: maskedBody, redacted } = masker.maskBody(rawBody, request.service);
      responseMsg = {
        id: request.id,
        status: upstreamResponse.status,
        headers: maskedHeaders,
        body: maskedBody,
        bodyEncoding: 'utf8',
        redacted
      };
    }
    
    logger.log({
      service: request.service,
      method: request.method,
      path: request.path,
      status: upstreamResponse.status,
      redacted: responseMsg.redacted,
      agent: request.agent
    });
    
    sendResponse(conn, responseMsg);
  } catch (err) {
    sendResponse(conn, {
      id: request.id, status: 502, headers: {}, body: '',
      bodyEncoding: 'utf8', error: `Upstream request failed: ${err.message}`
    });
  }
}

function sendResponse(conn: net.Socket, response: KeyholeResponse) {
  const payload = Buffer.from(JSON.stringify(response), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  conn.write(Buffer.concat([header, payload]));
}
```

### 5.3 Client-Side Socket Communication

```typescript
// src/client/ipc-client.ts

import net from 'net';

export class IPCClient {
  private socketPath: string;
  private ott: string;
  private pending = new Map<string, {
    resolve: (res: KeyholeResponse) => void;
    reject: (err: Error) => void;
  }>();
  private conn: net.Socket | null = null;
  private buffer = Buffer.alloc(0);
  private reconnecting = false;
  private reconnectAttempts = 0;
  private static MAX_RECONNECT_ATTEMPTS = 3;
  private static RECONNECT_DELAY_MS = 500;

  constructor(socketPath: string, ott: string) {
    this.socketPath = socketPath;
    this.ott = ott;
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.conn = net.createConnection(this.socketPath, () => {
        this.reconnectAttempts = 0;
        resolve();
      });
      this.conn.on('error', (err) => {
        if (!this.reconnecting) reject(err);
      });
      this.conn.on('close', () => this.handleDisconnect());
      this.conn.on('data', (data) => this.onData(data));
    });
  }

  /**
   * Handle unexpected socket disconnects (not from explicit shutdown).
   * Attempts automatic reconnection to the same socket path for transient
   * failures (e.g., brief OS-level interruption). This is distinct from
   * updateConnection(), which handles sidecar *restarts* with a new socket
   * path and OTT.
   */
  private async handleDisconnect(): Promise<void> {
    if (this.reconnecting) return;
    // If conn was explicitly destroyed (via disconnect()), do nothing
    if (!this.conn) return;
    
    this.reconnecting = true;
    this.conn = null;
    
    while (this.reconnectAttempts < IPCClient.MAX_RECONNECT_ATTEMPTS) {
      this.reconnectAttempts++;
      await new Promise(r => setTimeout(r, 
        IPCClient.RECONNECT_DELAY_MS * this.reconnectAttempts
      ));
      
      try {
        await this.connect();
        this.reconnecting = false;
        return;
      } catch {
        // Will retry
      }
    }
    
    // All reconnect attempts exhausted — fail all pending requests
    this.reconnecting = false;
    for (const [id, pending] of this.pending) {
      pending.reject(new Error(
        'IPC connection lost and reconnect failed after ' +
        `${IPCClient.MAX_RECONNECT_ATTEMPTS} attempts`
      ));
    }
    this.pending.clear();
  }

  private onData(data: Buffer) {
    this.buffer = Buffer.concat([this.buffer, data]);
    
    while (this.buffer.length >= 4) {
      const payloadLength = this.buffer.readUInt32BE(0);
      if (this.buffer.length < 4 + payloadLength) break;
      
      const payload = this.buffer.subarray(4, 4 + payloadLength);
      this.buffer = this.buffer.subarray(4 + payloadLength);
      
      const response = JSON.parse(payload.toString('utf-8')) as KeyholeResponse;
      const pending = this.pending.get(response.id);
      if (pending) {
        this.pending.delete(response.id);
        if (response.error) {
          pending.reject(new Error(response.error));
        } else {
          pending.resolve(response);
        }
      }
    }
  }

  async send(request: Omit<KeyholeRequest, 'ott'>): Promise<KeyholeResponse> {
    if (!this.conn) throw new Error('Not connected');
    
    const fullRequest: KeyholeRequest = { ...request, ott: this.ott };
    const payload = Buffer.from(JSON.stringify(fullRequest), 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    
    return new Promise((resolve, reject) => {
      this.pending.set(request.id, { resolve, reject });
      this.conn!.write(Buffer.concat([header, payload]));
      
      setTimeout(() => {
        if (this.pending.has(request.id)) {
          this.pending.delete(request.id);
          reject(new Error(
            `Request timed out: ${request.service} ${request.method} ${request.path}`
          ));
        }
      }, 30_000);
    });
  }

  async disconnect(): Promise<void> {
    if (this.conn) {
      const conn = this.conn;
      this.conn = null; // Set to null BEFORE destroy to signal intentional disconnect
      conn.destroy();
    }
  }

  /** Update connection after sidecar restart (new OTT and socket) */
  async updateConnection(socketPath: string, ott: string): Promise<void> {
    await this.disconnect();
    this.socketPath = socketPath;
    this.ott = ott;
    this.reconnectAttempts = 0;
    
    for (const [id, pending] of this.pending) {
      pending.reject(new Error('Sidecar restarted – request aborted'));
    }
    this.pending.clear();
    
    await this.connect();
  }
}
```

---

## 6. HTTP Interceptor

### 6.1 Overview

The interceptor patches Node.js's HTTP primitives to transparently route requests to 
keyhole-managed domains through the sidecar. It patches three targets:

1. `http.request` / `http.get`
2. `https.request` / `https.get`
3. `globalThis.fetch` (Node 18+ undici-based native fetch)

### 6.2 Binary Detection Utility

Both the `fetch` interceptor and `FakeClientRequest` need to determine whether a request
body is binary (requiring Base64 IPC encoding) or text (safe for UTF-8 IPC encoding).
This shared utility centralizes that logic.

```typescript
// src/client/binary-detect.ts

/**
 * Known text Content-Type prefixes. If a Content-Type starts with one of these,
 * the body is safe to encode as UTF-8 for IPC transport.
 */
const TEXT_CONTENT_TYPES = [
  'text/',
  'application/json',
  'application/xml',
  'application/x-www-form-urlencoded',
  'application/javascript',
  'application/graphql',
];

/**
 * Determine whether a request body should be treated as binary for IPC transport.
 * 
 * Returns true if the body must be Base64-encoded to avoid corruption.
 * Returns false if the body is safe to encode as UTF-8 string.
 */
export function isBodyBinary(
  contentType: string | undefined,
  body: Buffer | string | undefined
): boolean {
  // Strings are always text
  if (typeof body === 'string') return false;
  
  // No body — doesn't matter, but default to text
  if (!body) return false;
  
  // Check Content-Type first
  if (contentType) {
    const lower = contentType.toLowerCase();
    if (TEXT_CONTENT_TYPES.some(t => lower.startsWith(t) || lower.includes(t))) {
      return false;
    }
    // Explicit binary types
    if (lower.includes('application/octet-stream') ||
        lower.includes('image/') ||
        lower.includes('audio/') ||
        lower.includes('video/') ||
        lower.includes('multipart/')) {
      return true;
    }
  }
  
  // Fall back to byte sniffing for Buffers with unknown Content-Type
  if (Buffer.isBuffer(body)) {
    const sample = body.subarray(0, 512);
    for (let i = 0; i < sample.length; i++) {
      const byte = sample[i];
      if (byte === 0) return true;
      if (byte < 8 || (byte > 13 && byte < 32)) return true;
    }
  }
  
  return false;
}
```

### 6.3 Implementation

```typescript
// src/client/interceptor.ts

import http from 'http';
import https from 'https';
import { IPCClient } from './ipc-client';
import { ParsedConfig } from '../config/schema';
import { isBodyBinary } from './binary-detect';

export class Interceptor {
  private ipc: IPCClient;
  private config: ParsedConfig;
  
  // Simple domain → service lookup
  private domainMap: Map<string, string>;
  // Path-prefix domain → service lookup (for shared domains)
  private prefixMap: Map<string, Array<{ prefix: string; service: string }>>;
  
  private originals: {
    httpsRequest: typeof https.request;
    httpsGet: typeof https.get;
    httpRequest: typeof http.request;
    httpGet: typeof http.get;
    fetch: typeof globalThis.fetch;
  };
  
  private installed = false;

  constructor(ipc: IPCClient, config: ParsedConfig) {
    this.ipc = ipc;
    this.config = config;
    
    this.domainMap = new Map();
    this.prefixMap = new Map();
    
    for (const [name, service] of Object.entries(config.services)) {
      for (const domain of service.domains) {
        if (typeof domain === 'string') {
          this.domainMap.set(domain, name);
        } else {
          const existing = this.prefixMap.get(domain.host) || [];
          existing.push({ prefix: domain.path_prefix, service: name });
          existing.sort((a, b) => b.prefix.length - a.prefix.length);
          this.prefixMap.set(domain.host, existing);
        }
      }
    }
    
    this.originals = {
      httpsRequest: https.request,
      httpsGet: https.get,
      httpRequest: http.request,
      httpGet: http.get,
      fetch: globalThis.fetch
    };
  }

  install(): void {
    if (this.installed) return;
    this.patchHttpModule(https, 'httpsRequest', 'httpsGet');
    this.patchHttpModule(http, 'httpRequest', 'httpGet');
    this.patchFetch();
    this.installed = true;
  }

  uninstall(): void {
    if (!this.installed) return;
    https.request = this.originals.httpsRequest;
    https.get = this.originals.httpsGet;
    http.request = this.originals.httpRequest;
    http.get = this.originals.httpGet;
    globalThis.fetch = this.originals.fetch;
    this.installed = false;
  }

  private resolveService(hostname: string, pathname: string): string | null {
    const simple = this.domainMap.get(hostname);
    if (simple) return simple;
    
    const prefixed = this.prefixMap.get(hostname);
    if (prefixed) {
      for (const { prefix, service } of prefixed) {
        if (pathname.startsWith(prefix)) return service;
      }
    }
    
    return null;
  }

  private patchFetch(): void {
    const self = this;
    const originalFetch = this.originals.fetch;

    globalThis.fetch = async function(
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> {
      const url = typeof input === 'string' ? input 
        : input instanceof URL ? input.toString()
        : input.url;
      
      const parsed = new URL(url);
      const service = self.resolveService(parsed.hostname, parsed.pathname);
      
      if (!service) {
        return originalFetch.call(globalThis, input, init);
      }
      
      return self.routeFetchThroughSidecar(parsed, init, service);
    };
  }

  private async routeFetchThroughSidecar(
    parsed: URL,
    init: RequestInit | undefined,
    service: string
  ): Promise<Response> {
    const id = crypto.randomUUID();
    
    // Determine body encoding
    let body: string | undefined;
    let bodyBase64: string | undefined;
    let bodyEncoding: 'utf8' | 'base64' = 'utf8';
    
    if (init?.body) {
      const rawBody = typeof init.body === 'string' 
        ? Buffer.from(init.body) 
        : Buffer.isBuffer(init.body) 
          ? init.body 
          : Buffer.from(init.body as ArrayBuffer);
      
      // Enforce body size limit client-side
      if (rawBody.length > 10 * 1024 * 1024) {
        throw new Error('Request body exceeds Keyhole limit (10MB).');
      }
      
      const contentType = new Headers(init?.headers).get('content-type') || undefined;
      
      if (isBodyBinary(contentType, rawBody)) {
        bodyBase64 = rawBody.toString('base64');
        bodyEncoding = 'base64';
      } else {
        body = rawBody.toString('utf-8');
        bodyEncoding = 'utf8';
      }
    }
    
    const response = await this.ipc.send({
      id,
      service,
      method: init?.method || 'GET',
      path: parsed.pathname + parsed.search,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body,
      bodyBase64,
      bodyEncoding
    });
    
    // Handle binary responses
    if (response.bodyEncoding === 'base64' && response.bodyBase64) {
      return new Response(Buffer.from(response.bodyBase64, 'base64'), {
        status: response.status,
        headers: response.headers
      });
    }
    
    return new Response(response.body, {
      status: response.status,
      headers: response.headers
    });
  }

  // patchHttpModule and FakeClientRequest handle the http/https.request path
  // See section 6.4
}
```

### 6.4 The http.ClientRequest Compatibility Shim

`http.request` and `https.request` return a `ClientRequest` object with a writable stream 
interface. The interceptor must return a compatible object.

**Compatibility scope:** `FakeClientRequest` implements the subset of `http.ClientRequest`
that real-world SDKs depend on. This includes the full writable stream lifecycle (`write`,
`end`, `destroy`), flow control stubs (`cork`/`uncork`, `setNoDelay`), and pipe support
via `_write`. Methods that are meaningless in a proxied context (e.g., `setSocketKeepAlive`,
`setTimeout` on a non-socket) are no-ops. If an SDK relies on lower-level socket behavior
(direct `socket` property access, raw TLS events), it should use `createClient()` instead
of `autoPatch`.

```typescript
// src/client/fake-request.ts

import { Readable, Writable } from 'stream';
import { isBodyBinary } from './binary-detect';

export class FakeClientRequest extends Writable {
  private bodyChunks: Buffer[] = [];
  private totalSize = 0;
  private ipc: IPCClient;
  private service: string;
  private method: string;
  private path: string;
  private headers: Record<string, string>;
  private responseCallback?: (res: any) => void;
  
  public headersSent = false;
  public finished = false;
  public aborted = false;

  private static MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB

  constructor(
    ipc: IPCClient,
    service: string,
    method: string,
    path: string,
    headers: Record<string, string>,
    callback?: (res: any) => void
  ) {
    super();
    this.ipc = ipc;
    this.service = service;
    this.method = method;
    this.path = path;
    this.headers = headers;
    this.responseCallback = callback;
  }

  /**
   * Writable stream _write implementation.
   * This enables pipe() support: readable.pipe(fakeRequest) works correctly
   * because Writable base class calls _write for each chunk.
   */
  _write(chunk: Buffer | string, encoding: string, callback: (error?: Error | null) => void): void {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding as BufferEncoding);
    this.totalSize += buf.length;
    
    if (this.totalSize > FakeClientRequest.MAX_BODY_SIZE) {
      const err = new Error(
        `Request body exceeds Keyhole limit (${FakeClientRequest.MAX_BODY_SIZE} bytes). ` +
        `For large uploads, use keyhole.createClient() with streaming support (v1.5).`
      );
      callback(err);
      return;
    }
    
    this.bodyChunks.push(buf);
    callback(null);
  }

  /**
   * Legacy write() for direct call compatibility (e.g., req.write(chunk)).
   * SDKs may call this directly instead of piping.
   */
  write(chunk: Buffer | string, encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void): boolean {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.totalSize += buf.length;
    
    // Enforce body size limit HERE, not in the sidecar.
    if (this.totalSize > FakeClientRequest.MAX_BODY_SIZE) {
      const err = new Error(
        `Request body exceeds Keyhole limit (${FakeClientRequest.MAX_BODY_SIZE} bytes). ` +
        `For large uploads, use keyhole.createClient() with streaming support (v1.5).`
      );
      this.emit('error', err);
      return false;
    }
    
    this.bodyChunks.push(buf);
    return true;
  }

  /**
   * _final is called by the Writable base class when end() is called.
   * This is where we send the accumulated body to the sidecar.
   *
   * Binary safety: The body is inspected via Content-Type and byte sniffing.
   * Binary payloads (images, protobuf, etc.) are Base64-encoded for IPC to
   * prevent corruption from UTF-8 encoding. Text payloads use UTF-8.
   */
  _final(callback: (error?: Error | null) => void): void {
    this.headersSent = true;
    this.finished = true;
    
    const rawBody = Buffer.concat(this.bodyChunks);
    const id = crypto.randomUUID();
    
    // Determine encoding: binary bodies must be Base64 to avoid corruption
    const contentType = this.headers['content-type'] || this.headers['Content-Type'];
    const binary = isBodyBinary(contentType, rawBody);
    
    const ipcMessage: Omit<KeyholeRequest, 'ott'> = {
      id,
      service: this.service,
      method: this.method,
      path: this.path,
      headers: this.headers,
      bodyEncoding: binary ? 'base64' : 'utf8',
    };
    
    if (binary) {
      ipcMessage.bodyBase64 = rawBody.toString('base64');
    } else {
      ipcMessage.body = rawBody.toString('utf-8');
    }
    
    this.ipc.send(ipcMessage).then((response) => {
      const readable = new Readable({
        read() {
          if (response.bodyEncoding === 'base64' && response.bodyBase64) {
            this.push(Buffer.from(response.bodyBase64, 'base64'));
          } else {
            this.push(response.body);
          }
          this.push(null);
        }
      });
      
      (readable as any).statusCode = response.status;
      (readable as any).headers = response.headers;
      (readable as any).statusMessage = '';

      if (this.responseCallback) this.responseCallback(readable);
      this.emit('response', readable);
      callback(null);
    }).catch((err) => {
      callback(err);
    });
  }

  /**
   * _destroy is called when destroy() is called or on error.
   * Cleans up resources and rejects any in-flight state.
   */
  _destroy(err: Error | null, callback: (error?: Error | null) => void): void {
    this.aborted = true;
    this.bodyChunks = [];
    this.totalSize = 0;
    callback(err);
  }

  abort(): void {
    this.aborted = true;
    this.destroy();
    this.emit('abort');
  }
  
  setHeader(name: string, value: string): void { this.headers[name] = value; }
  getHeader(name: string): string | undefined { return this.headers[name]; }
  removeHeader(name: string): void { delete this.headers[name]; }
  
  // No-ops: these are meaningless in a proxied context but SDKs may call them.
  setTimeout(ms: number, cb?: () => void): this { return this; }
  setNoDelay(noDelay?: boolean): void {}
  setSocketKeepAlive(enable?: boolean, initial?: number): void {}
  flushHeaders(): void { this.headersSent = true; }
}
```

---

## 7. Request Builder

### 7.1 Responsibilities

The request builder runs inside the sidecar process. It takes a `KeyholeRequest` and 
produces a real outbound HTTP request with:

1. The correct base URL from config
2. Real credentials injected
3. Service-specific headers added
4. All agent-provided auth headers stripped
5. A minimal, constructed set of headers (no agent header passthrough)

### 7.2 Auth Injection Strategies

```typescript
// src/sidecar/request-builder.ts

type AuthStrategy = 
  | { type: 'bearer'; secret_ref: string }
  | { type: 'basic'; secret_ref: string; username?: string }
  | { type: 'query_param'; param_name: string; secret_ref: string }
  | { type: 'custom_header'; header_name: string; secret_ref: string };

class RequestBuilder {
  private config: ParsedConfig;
  private secrets: Map<string, string>;

  constructor(config: ParsedConfig, secrets: Map<string, string>) {
    this.config = config;
    this.secrets = secrets;
  }

  build(request: KeyholeRequest): { url: string; options: RequestInit } {
    const service = this.config.services[request.service];
    if (!service) throw new Error(`Unknown service: ${request.service}`);
    
    let url = service.base_url.replace(/\/$/, '') + request.path;
    
    const secret = this.secrets.get(service.auth.secret_ref);
    if (!secret) throw new Error(`Secret not resolved for: ${service.auth.secret_ref}`);
    
    const headers: Record<string, string> = {};
    
    switch (service.auth.type) {
      case 'bearer':
        headers['Authorization'] = `Bearer ${secret}`;
        break;
      case 'basic':
        if (service.auth.username) {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${service.auth.username}:${secret}`
          ).toString('base64')}`;
        } else {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${secret}:`
          ).toString('base64')}`;
        }
        break;
      case 'query_param': {
        const urlObj = new URL(url);
        urlObj.searchParams.set(service.auth.param_name, secret);
        url = urlObj.toString();
        break;
      }
      case 'custom_header':
        headers[service.auth.header_name] = secret;
        break;
    }
    
    if (service.headers) Object.assign(headers, service.headers);
    headers['User-Agent'] = 'agent-keyhole/1.0';
    
    // Whitelist: only forward Content-Type and Accept from agent
    if (request.headers['content-type']) {
      headers['Content-Type'] = request.headers['content-type'];
    }
    if (request.headers['accept'] && !headers['Accept']) {
      headers['Accept'] = request.headers['accept'];
    }
    
    // Decode binary body from Base64 back to raw bytes for upstream
    let body: string | Buffer | undefined;
    if (request.bodyEncoding === 'base64' && request.bodyBase64) {
      body = Buffer.from(request.bodyBase64, 'base64');
    } else {
      body = request.body || undefined;
    }
    
    return {
      url,
      options: {
        method: request.method,
        headers,
        body
      }
    };
  }
  
  /**
   * Build auth headers for a specific service. Used by redirect handler to
   * re-inject credentials when a redirect chain returns to a trusted domain.
   */
  buildAuthHeaders(serviceName: string): Record<string, string> {
    const service = this.config.services[serviceName];
    if (!service) return {};
    
    const secret = this.secrets.get(service.auth.secret_ref);
    if (!secret) return {};
    
    const headers: Record<string, string> = {};
    
    switch (service.auth.type) {
      case 'bearer':
        headers['Authorization'] = `Bearer ${secret}`;
        break;
      case 'basic':
        if (service.auth.username) {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${service.auth.username}:${secret}`
          ).toString('base64')}`;
        } else {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${secret}:`
          ).toString('base64')}`;
        }
        break;
      case 'custom_header':
        headers[service.auth.header_name] = secret;
        break;
      // query_param is handled via URL, not headers — no re-injection needed here
    }
    
    return headers;
  }
  
  /**
   * Re-inject query_param auth into a URL. Used by redirect handler when
   * a redirect chain returns to a trusted domain.
   */
  injectQueryParamAuth(url: URL, serviceName: string): void {
    const service = this.config.services[serviceName];
    if (!service || service.auth.type !== 'query_param') return;
    
    const secret = this.secrets.get(service.auth.secret_ref);
    if (!secret) return;
    
    url.searchParams.set(service.auth.param_name, secret);
  }
  
  getInjectedSecrets(): string[] { return Array.from(this.secrets.values()); }
  getSecrets(): Map<string, string> { return this.secrets; }
  getServiceConfig(name: string): ServiceConfig { return this.config.services[name]; }
}
```

### 7.3 Redirect Handling (Security-Critical)

**Vulnerability:** If the upstream API returns a 3xx redirect to a different domain, the 
standard `fetch` client follows the redirect and re-attaches the `Authorization` header.
This leaks real credentials to untrusted third parties. Real-world example: GitHub redirects 
release asset downloads to S3 URLs.

**Mitigation:** All outbound requests use `redirect: 'manual'`. Redirects are handled 
explicitly with domain validation.

**Trusted re-entry:** If a redirect chain passes through an untrusted domain (e.g., a CDN
or link-shortener) and then redirects *back* to a trusted domain for the same service,
credentials are **re-injected** for the trusted hop. This handles real-world patterns like
`api.github.com → cdn.example.com → api.github.com`. The trust evaluation and credential
injection happen independently on every hop.

```typescript
const MAX_REDIRECTS = 10;

async function fetchWithRedirectPolicy(
  url: string,
  options: RequestInit,
  service: ServiceConfig,
  secrets: Map<string, string>,
  builder: RequestBuilder,
  redirectCount = 0
): Promise<Response> {
  if (redirectCount > MAX_REDIRECTS) {
    throw new Error(`Too many redirects (>${MAX_REDIRECTS})`);
  }

  const response = await fetch(url, { ...options, redirect: 'manual' });

  if (![301, 302, 303, 307, 308].includes(response.status)) {
    return response;
  }

  const location = response.headers.get('location');
  if (!location) return response;

  const redirectUrl = new URL(location, url);
  const redirectHost = redirectUrl.hostname;

  // Determine the service name for this redirect's service config.
  // We need the service name to call buildAuthHeaders / injectQueryParamAuth.
  const serviceName = Object.entries(builder['config'].services)
    .find(([_, s]) => s === service)?.[0];

  const isTrusted = service.domains.some(d => 
    (typeof d === 'string' ? d : d.host) === redirectHost
  );

  if (isTrusted) {
    // Trusted domain: ensure credentials are present (re-inject if previously stripped)
    const authHeaders = serviceName ? builder.buildAuthHeaders(serviceName) : {};
    const currentHeaders = { ...(options.headers as Record<string, string>), ...authHeaders };
    
    if (serviceName) builder.injectQueryParamAuth(redirectUrl, serviceName);
    
    return fetchWithRedirectPolicy(
      redirectUrl.toString(),
      { ...options, headers: currentHeaders },
      service, secrets, builder, redirectCount + 1
    );
  } else {
    // UNTRUSTED domain – Strip everything except safe metadata (Whitelist approach)
    const whitelist = ['content-type', 'accept', 'user-agent'];
    const safeHeaders: Record<string, string> = {};
    
    const inputHeaders = options.headers as Record<string, string>;
    for (const key of Object.keys(inputHeaders)) {
      if (whitelist.includes(key.toLowerCase())) {
        safeHeaders[key] = inputHeaders[key];
      }
    }
    
    // Explicitly delete query_param auth if applicable
    if (service.auth.type === 'query_param') {
      redirectUrl.searchParams.delete(service.auth.param_name);
    }
    
    return fetchWithRedirectPolicy(
      redirectUrl.toString(),
      { ...options, headers: safeHeaders },
      service, secrets, builder, redirectCount + 1
    );
  }
}
```

### 7.4 Header Passthrough Policy

**Forwarded from agent (whitelist):**
- `Content-Type` (needed for request body parsing)
- `Accept` (only if not already set by service config)

**Set by sidecar (always):**
- `Authorization` or equivalent (from secret injection)
- `User-Agent`: `agent-keyhole/1.0`
- Service-specific headers from config

**Never forwarded:**
- `Authorization`, `Proxy-Authorization` (replaced by sidecar)
- `Cookie`, `Set-Cookie`
- `X-*` custom headers from agent
- `Referer`, `Origin`
- Any other agent-provided header

This is a strict whitelist, not a blacklist.

---

## 8. Response Masker

### 8.1 Overview

The response masker runs inside the sidecar and applies four layers of redaction before 
any response data reaches the agent process.

### 8.2 Layer 1: Header Scrubbing

Always active, zero configuration.

```typescript
const SCRUB_RESPONSE_HEADERS = new Set([
  'authorization', 'www-authenticate', 'proxy-authorization',
  'proxy-authenticate', 'set-cookie', 'cookie', 'x-api-key',
  'x-amz-security-token', 'x-amz-credential', 'x-csrf-token', 'x-xsrf-token',
]);

function scrubHeaders(headers: Record<string, string>): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!SCRUB_RESPONSE_HEADERS.has(key.toLowerCase())) {
      clean[key] = value;
    }
  }
  return clean;
}
```

### 8.3 Layer 2: Known-Secret Body Scan

Always active. Scans response body for exact matches of secrets the sidecar injected.

```typescript
const REDACTION_MARKER = '[REDACTED BY KEYHOLE]';
const MIN_SECRET_LENGTH = 8;

function maskKnownSecrets(
  body: string, injectedSecrets: string[]
): { body: string; redacted: boolean } {
  let masked = body;
  let redacted = false;
  
  for (const secret of injectedSecrets) {
    if (secret.length < MIN_SECRET_LENGTH) continue;
    
    if (masked.includes(secret)) {
      masked = masked.replaceAll(secret, REDACTION_MARKER);
      redacted = true;
    }
    
    const b64 = Buffer.from(secret).toString('base64');
    if (masked.includes(b64)) {
      masked = masked.replaceAll(b64, REDACTION_MARKER);
      redacted = true;
    }
    
    const urlEncoded = encodeURIComponent(secret);
    if (urlEncoded !== secret && masked.includes(urlEncoded)) {
      masked = masked.replaceAll(urlEncoded, REDACTION_MARKER);
      redacted = true;
    }
  }
  
  return { body: masked, redacted };
}
```

### 8.4 Layer 3: Pattern-Based Redaction

Configurable per-service. Catches credential patterns in responses even if they don't match 
the specific injected secret (e.g., API returns a new token).

```typescript
function maskPatterns(
  body: string, patterns: string[]
): { body: string; redacted: boolean } {
  let masked = body;
  let redacted = false;
  
  for (const pattern of patterns) {
    const regex = new RegExp(pattern, 'g');
    if (regex.test(masked)) {
      masked = masked.replace(new RegExp(pattern, 'g'), REDACTION_MARKER);
      redacted = true;
    }
  }
  
  return { body: masked, redacted };
}
```

### 8.5 Layer 4: JSON Path Redaction

Configurable per-service via `json_paths`. Targets specific JSON keys/paths in response
bodies, catching credentials that may not match known patterns (e.g., a rotating token
returned in a known field).

**JSON path syntax:** A subset of JSONPath using dot-notation with `$` as root.
- `$.token` — top-level key `token`
- `$.credentials.access_token` — nested path
- `$.data[*].secret` — array wildcard (all elements)

```typescript
const REDACTION_MARKER = '[REDACTED BY KEYHOLE]';

/**
 * Redact values at specified JSON paths in a parsed JSON object.
 * Mutates the object in-place and returns whether any redaction occurred.
 */
function redactJsonPaths(obj: any, paths: string[]): boolean {
  let redacted = false;
  
  for (const path of paths) {
    const segments = parseJsonPath(path);
    if (segments.length === 0) continue;
    redacted = walkAndRedact(obj, segments, 0) || redacted;
  }
  
  return redacted;
}

/**
 * Parse a JSONPath string into path segments.
 * Supports: $.foo.bar, $.foo[*].bar, $.foo[0].bar
 */
function parseJsonPath(path: string): Array<string | '*'> {
  // Strip leading "$." or "$"
  let p = path.startsWith('$.') ? path.slice(2) : path.startsWith('$') ? path.slice(1) : path;
  
  const segments: Array<string | '*'> = [];
  const parts = p.split(/\.|\[|\]/).filter(s => s !== '');
  
  for (const part of parts) {
    if (part === '*') {
      segments.push('*');
    } else {
      segments.push(part);
    }
  }
  
  return segments;
}

/**
 * Recursively walk an object and redact values at the target path.
 */
function walkAndRedact(obj: any, segments: Array<string | '*'>, index: number): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (index >= segments.length) return false;
  
  const segment = segments[index];
  const isLast = index === segments.length - 1;
  
  if (segment === '*') {
    // Wildcard: iterate all elements (array) or all values (object)
    let redacted = false;
    // Fix: Object.keys works safely for both objects and arrays (returning index strings)
    const keys = Object.keys(obj); 
    for (const key of keys) {
      if (isLast) {
        if (obj[key] !== undefined && typeof obj[key] === 'string') {
          obj[key] = REDACTION_MARKER;
          redacted = true;
        }
      } else {
        redacted = walkAndRedact(obj[key], segments, index + 1) || redacted;
      }
    }
    return redacted;
  }
  
  if (isLast) {
    if (segment in obj && typeof obj[segment] === 'string') {
      obj[segment] = REDACTION_MARKER;
      return true;
    }
    return false;
  }
  
  return walkAndRedact(obj[segment], segments, index + 1);
}

/**
 * Apply JSON path redaction to a response body string.
 * Only applies if body is valid JSON. Non-JSON bodies are returned unmodified.
 */
function maskJsonPaths(
  body: string, jsonPaths: string[]
): { body: string; redacted: boolean } {
  let parsed: any;
  try {
    parsed = JSON.parse(body);
  } catch {
    // Not valid JSON — skip JSON path masking
    return { body, redacted: false };
  }
  
  const redacted = redactJsonPaths(parsed, jsonPaths);
  
  if (redacted) {
    return { body: JSON.stringify(parsed), redacted: true };
  }
  
  return { body, redacted: false };
}
```

### 8.6 Combined Masking Pipeline

```typescript
class ResponseMasker {
  private config: ParsedConfig;
  private injectedSecrets: string[];
  private placeholders: Set<string>;
  
  constructor(config: ParsedConfig, secrets: Map<string, string>) {
    this.config = config;
    this.injectedSecrets = Array.from(secrets.values());
    
    // Placeholder values should NOT be redacted
    this.placeholders = new Set(
      Object.values(config.services)
        .map(s => s.placeholder || 'KEYHOLE_MANAGED')
    );
  }
  
  scrubHeaders(headers: Record<string, string>): Record<string, string> {
    return scrubHeaders(headers);
  }
  
  maskBody(body: string, serviceName: string): { body: string; redacted: boolean } {
    let result = body;
    let anyRedacted = false;
    
    // Layer 2: Known secrets (excluding placeholders)
    const realSecrets = this.injectedSecrets.filter(s => !this.placeholders.has(s));
    const l2 = maskKnownSecrets(result, realSecrets);
    result = l2.body;
    anyRedacted = anyRedacted || l2.redacted;
    
    // Layer 3: Service-specific patterns
    const service = this.config.services[serviceName];
    if (service?.response_masking?.patterns) {
      const l3 = maskPatterns(result, service.response_masking.patterns);
      result = l3.body;
      anyRedacted = anyRedacted || l3.redacted;
    }
    
    // Layer 4: JSON path redaction
    if (service?.response_masking?.json_paths) {
      const l4 = maskJsonPaths(result, service.response_masking.json_paths);
      result = l4.body;
      anyRedacted = anyRedacted || l4.redacted;
    }
    
    return { body: result, redacted: anyRedacted };
  }
  
  /** Check if response is binary. Uses Content-Type then falls back to byte sniffing. */
  isBinaryResponse(contentType: string, bodyStart?: Buffer): boolean {
    if (contentType) {
      const textTypes = ['text/', 'application/json', 'application/xml',
                         'application/x-www-form-urlencoded', 'application/javascript'];
      if (textTypes.some(t => contentType.toLowerCase().includes(t))) return false;
      if (contentType.toLowerCase().includes('application/octet-stream')) return true;
      if (contentType.toLowerCase().includes('image/')) return true;
      if (contentType.toLowerCase().includes('audio/')) return true;
      if (contentType.toLowerCase().includes('video/')) return true;
    }
    
    if (bodyStart) {
      const sample = bodyStart.subarray(0, 512);
      for (let i = 0; i < sample.length; i++) {
        const byte = sample[i];
        if (byte === 0) return true;
        if (byte < 8 || (byte > 13 && byte < 32)) return true;
      }
    }
    
    return false;
  }
}
```

### 8.7 Streaming Support: Sliding Window Buffer

When responses are streamed, secrets may be split across chunk boundaries.

**Note on Layer 4 (JSON path) and streaming:** JSON path redaction requires a complete,
parseable JSON document. It cannot operate on partial chunks. When streaming mode is active,
Layer 4 is **deferred to flush time** — the full accumulated buffer is JSON-path-redacted
during `flush()`. The `jsonPathAccumulator` is capped at `MAX_ACCUMULATOR_SIZE` (10MB) to
prevent OOM from large API responses. If the accumulated response exceeds this limit, Layer
4 is skipped for that response and a warning is logged. For guaranteed JSON path coverage on
large responses, set `response_masking.streaming: buffer`.

```typescript
/** Default cap for unbounded regex quantifiers in streaming mode. Configurable per-service. */
const DEFAULT_STREAMING_WINDOW_CAP = 200;

/** Maximum size of the JSON path accumulator before L4 is skipped (OOM protection). */
const MAX_ACCUMULATOR_SIZE = 10 * 1024 * 1024; // 10MB

class StreamingMasker {
  private windowSize: number;
  private buffer: string = '';
  private masker: ResponseMasker;
  private serviceName: string;
  private hasJsonPaths: boolean;
  private jsonPathAccumulator: string = '';
  private jsonPathAccumulatorOverflow = false;
  private logger: AuditLogger;

  constructor(
    masker: ResponseMasker, secrets: string[], 
    serviceName: string, config: ParsedConfig,
    logger: AuditLogger
  ) {
    this.masker = masker;
    this.serviceName = serviceName;
    this.logger = logger;
    
    const service = config.services[serviceName];
    this.hasJsonPaths = !!(service?.response_masking?.json_paths?.length);
    
    // Configurable cap for unbounded quantifiers (default: 200).
    // If a service has patterns like `token_[a-f0-9]{256}`, increase this value
    // in the service config to ensure full coverage in streaming mode.
    const windowCap = service?.response_masking?.streaming_window_cap 
      ?? DEFAULT_STREAMING_WINDOW_CAP;
    
    // Window = max of (longest secret across encodings, longest regex match estimate)
    this.windowSize = 0;
    
    for (const secret of secrets) {
      this.windowSize = Math.max(this.windowSize,
        secret.length,
        Buffer.from(secret).toString('base64').length,
        encodeURIComponent(secret).length
      );
    }
    
    if (service?.response_masking?.patterns) {
      for (const pattern of service.response_masking.patterns) {
        this.windowSize = Math.max(
          this.windowSize, estimateMaxMatchLength(pattern, windowCap)
        );
      }
    }
    
    this.windowSize += 10; // Safety margin
  }
  
  processChunk(chunk: string): { output: string; redacted: boolean } {
    const combined = this.buffer + chunk;
    
    // Accumulate for deferred JSON path redaction (with OOM protection)
    if (this.hasJsonPaths && !this.jsonPathAccumulatorOverflow) {
      if (this.jsonPathAccumulator.length + chunk.length > MAX_ACCUMULATOR_SIZE) {
        this.jsonPathAccumulatorOverflow = true;
        this.jsonPathAccumulator = ''; // Free memory immediately
        this.logger.warn(
          `Response for service "${this.serviceName}" exceeded ${MAX_ACCUMULATOR_SIZE} bytes. ` +
          `Layer 4 (json_paths) masking will be skipped for this response. ` +
          `Layers 2 and 3 still apply. Consider using "streaming: buffer" for this service.`
        );
      } else {
        this.jsonPathAccumulator += chunk;
      }
    }
    
    if (combined.length <= this.windowSize) {
      this.buffer = combined;
      return { output: '', redacted: false };
    }
    
    const safeLength = combined.length - this.windowSize;
    const safeRegion = combined.substring(0, safeLength);
    this.buffer = combined.substring(safeLength);
    
    // Apply L2 and L3 only during streaming; L4 is deferred to flush
    return this.masker.maskBody(safeRegion, this.serviceName);
  }
  
  flush(): { output: string; redacted: boolean } {
    let result = this.buffer;
    this.buffer = '';
    
    // Apply L2 and L3
    let { body: masked, redacted } = this.masker.maskBody(result, this.serviceName);
    
    // Apply deferred L4 (JSON path) on full accumulated response
    if (this.hasJsonPaths && !this.jsonPathAccumulatorOverflow && this.jsonPathAccumulator) {
      const service = this.masker['config'].services[this.serviceName];
      if (service?.response_masking?.json_paths) {
        const l4 = maskJsonPaths(this.jsonPathAccumulator, service.response_masking.json_paths);
        if (l4.redacted) {
          // Re-run the full pipeline on the complete body for consistency
          masked = l4.body;
          redacted = true;
        }
      }
      this.jsonPathAccumulator = '';
    }
    
    return { output: masked, redacted };
  }
}

function estimateMaxMatchLength(pattern: string, cap: number): number {
  let p = pattern.replace(/^\^|\$$/g, '');
  let length = 0;
  let i = 0;
  
  while (i < p.length) {
    if (p[i] === '[') {
      const end = p.indexOf(']', i);
      if (end === -1) { length += 1; i++; continue; }
      i = end + 1;
      const q = parseQuantifier(p, i, cap);
      length += q.max;
      i = q.nextIndex;
    } else if (p[i] === '\\') {
      i += 2;
      const q = parseQuantifier(p, i, cap);
      length += q.max;
      i = q.nextIndex;
    } else {
      i++;
      const q = parseQuantifier(p, i, cap);
      length += q.max;
      i = q.nextIndex;
    }
  }
  return length;
}

function parseQuantifier(
  p: string, i: number, cap: number
): { max: number; nextIndex: number } {
  if (i >= p.length) return { max: 1, nextIndex: i };
  if (p[i] === '{') {
    const end = p.indexOf('}', i);
    if (end !== -1) {
      const inner = p.substring(i + 1, end);
      const parts = inner.split(',');
      const max = parts.length > 1 ? parseInt(parts[1] || String(cap)) : parseInt(parts[0]);
      return { max: isNaN(max) ? cap : max, nextIndex: end + 1 };
    }
  }
  if (p[i] === '+' || p[i] === '*') return { max: cap, nextIndex: i + 1 };
  if (p[i] === '?') return { max: 1, nextIndex: i + 1 };
  return { max: 1, nextIndex: i };
}
```

**Streaming Layer 3 Limitation:** For regex patterns with unbounded quantifiers (`+`, `*`),
the sliding window caps at `streaming_window_cap` characters (default: 200). This default
is sufficient for most API key patterns but may be insufficient for very long tokens (e.g.,
JWTs). Configure `streaming_window_cap` per-service if your patterns may match strings
longer than 200 characters. For guaranteed coverage, set `response_masking.streaming: buffer` 
in config to force full response buffering.

---

## 9. Client Factory

### 9.1 `createClient(serviceName)`

Returns a function with the same signature as `fetch`, scoped to a specific service and 
routed through IPC.

```typescript
// src/client/create-client.ts

export type KeyholeClient = (
  path: string, 
  init?: { method?: string; headers?: Record<string, string>; body?: string; }
) => Promise<Response>;

export function createClient(ipc: IPCClient, serviceName: string): KeyholeClient {
  return async (path: string, init?: any): Promise<Response> => {
    const id = crypto.randomUUID();
    
    const response = await ipc.send({
      id, service: serviceName,
      method: init?.method || 'GET', path,
      headers: init?.headers || {},
      body: init?.body, bodyEncoding: 'utf8'
    });
    
    if (response.bodyEncoding === 'base64' && response.bodyBase64) {
      return new Response(Buffer.from(response.bodyBase64, 'base64'), {
        status: response.status, headers: response.headers
      });
    }
    
    return new Response(response.body, {
      status: response.status, headers: response.headers
    });
  };
}
```

---

## 10. Safe Environment Generator

### 10.1 `getSafeEnv()`

Returns placeholder environment variables for legacy SDK compatibility.

```typescript
// src/client/safe-env.ts

export function generateSafeEnv(config: ParsedConfig): Record<string, string> {
  const env: Record<string, string> = {};
  
  for (const [name, service] of Object.entries(config.services)) {
    if (service.sdk_env) {
      for (const [envVar, template] of Object.entries(service.sdk_env)) {
        env[envVar] = template.replace(
          '{{placeholder}}', 
          service.placeholder || 'KEYHOLE_MANAGED'
        );
      }
    }
  }
  
  return env;
}
```

---

## 11. Configuration Schema

### 11.1 YAML Format

```yaml
# keyhole.yaml – complete example

services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    placeholder: "KEYHOLE_MANAGED"
    sdk_env:
      GITHUB_TOKEN: "{{placeholder}}"
    headers:
      Accept: application/vnd.github+json
      X-GitHub-Api-Version: "2022-11-28"
    response_masking:
      patterns:
        - "ghp_[A-Za-z0-9_]{36}"
        - "gho_[A-Za-z0-9_]{36}"
        - "ghs_[A-Za-z0-9_]{36}"
      json_paths:
        - "$.token"
        - "$.credentials.access_token"

  openai:
    domains:
      - api.openai.com
    auth:
      type: bearer
      secret_ref: openai-api-key
    placeholder: "sk-keyhole-000000000000000000000000000000000000000000000000"
    sdk_env:
      OPENAI_API_KEY: "{{placeholder}}"
    response_masking:
      patterns:
        - "sk-[A-Za-z0-9]{20,}"

  gemini:
    domains:
      - generativelanguage.googleapis.com
    auth:
      type: query_param
      param_name: key
      secret_ref: gemini-api-key
    placeholder: "KEYHOLE_MANAGED"
    sdk_env:
      GEMINI_API_KEY: "{{placeholder}}"
    response_masking:
      patterns:
        - "AIza[A-Za-z0-9_-]{35}"

  stripe:
    domains:
      - api.stripe.com
    auth:
      type: basic
      secret_ref: stripe-secret-key
    placeholder: "sk_test_keyhole_placeholder_000000000000"
    sdk_env:
      STRIPE_SECRET_KEY: "{{placeholder}}"
    response_masking:
      patterns:
        - "sk_live_[A-Za-z0-9]{24,}"
        - "sk_test_[A-Za-z0-9]{24,}"

  anthropic:
    domains:
      - api.anthropic.com
    auth:
      type: custom_header
      header_name: x-api-key
      secret_ref: anthropic-api-key
    placeholder: "sk-ant-keyhole-000000000000000000000000000000000000"
    sdk_env:
      ANTHROPIC_API_KEY: "{{placeholder}}"
    response_masking:
      patterns:
        - "sk-ant-[A-Za-z0-9_-]{90,}"

  # Local service example — uses http:// protocol
  # ollama:
  #   base_url: "http://localhost:11434"
  #   domains:
  #     - localhost:11434
  #   auth:
  #     type: bearer
  #     secret_ref: ollama-token

  # Path-prefix matching for shared-domain enterprise APIs
  # enterprise-github:
  #   domains:
  #     - host: api.enterprise.com
  #       path_prefix: /github
  #   auth:
  #     type: bearer
  #     secret_ref: enterprise-github-token

  # Example: Service with long tokens requiring larger streaming window
  # long-token-service:
  #   domains:
  #     - api.long-tokens.example.com
  #   auth:
  #     type: bearer
  #     secret_ref: long-token
  #   response_masking:
  #     patterns:
  #       - "eyJ[A-Za-z0-9_-]{500,}"    # JWT pattern
  #     streaming_window_cap: 600         # Override default 200 for long JWTs

# Optional: Multi-agent access control
agents:
  content-bot:
    services: [github, openai, anthropic]
  deploy-bot:
    services: [github, stripe]

# Optional: Logging configuration
logging:
  output: stderr            # stderr | stdout | <filepath>
  level: info               # debug | info | warn | error
  verbose: false

# Optional: Alerting for VPS deployments
# alerting:
#   webhook_url: https://discord.com/api/webhooks/xxx/yyy
#   message_prefix: "production-moltbot"

# Optional: Socket directory override
# socket_dir: /run/user/1000
```

### 11.2 TypeScript Schema

```typescript
// src/config/schema.ts

export interface KeyholeConfig {
  services: Record<string, ServiceConfig>;
  agents?: Record<string, AgentConfig>;
  logging?: LoggingConfig;
  alerting?: AlertingConfig;
  socket_dir?: string;
}

export interface ServiceConfig {
  domains: Array<string | DomainWithPrefix>;
  auth: AuthConfig;
  placeholder?: string;
  sdk_env?: Record<string, string>;
  headers?: Record<string, string>;
  response_masking?: ResponseMaskingConfig;
  base_url?: string;  // Derived from first domain if not set explicitly
}

export interface DomainWithPrefix {
  host: string;
  path_prefix: string;
}

export type AuthConfig =
  | { type: 'bearer'; secret_ref: string }
  | { type: 'basic'; secret_ref: string; username?: string }
  | { type: 'query_param'; param_name: string; secret_ref: string }
  | { type: 'custom_header'; header_name: string; secret_ref: string };

export interface ResponseMaskingConfig {
  patterns?: string[];
  json_paths?: string[];
  streaming?: 'stream' | 'buffer';  // default: 'stream' (best-effort L3/L4)
  /** 
   * Maximum assumed match length for unbounded regex quantifiers (+, *) in streaming mode.
   * Default: 200. Increase if your patterns may match strings longer than 200 characters
   * (e.g., JWTs, long-lived session tokens). Only relevant when streaming != 'buffer'.
   */
  streaming_window_cap?: number;
}

export interface AgentConfig {
  services: string[];
}

export interface LoggingConfig {
  output?: 'stderr' | 'stdout' | string;
  level?: 'debug' | 'info' | 'warn' | 'error';
  verbose?: boolean;
}

export interface AlertingConfig {
  webhook_url?: string;
  message_prefix?: string;
}

export interface ParsedConfig extends KeyholeConfig {
  _domainToService: Map<string, string>;
  _secretRefs: string[];
}
```

### 11.3 Config Loader & Validator

```typescript
// src/config/loader.ts

import fs from 'fs';
import yaml from 'js-yaml';

/**
 * Determine if a hostname refers to a local/internal service.
 * Used to decide default protocol (http vs https) when base_url is not explicit.
 */
function isLocalHost(host: string): boolean {
  // Strip port if present
  const hostname = host.split(':')[0];
  
  if (hostname === 'localhost') return true;
  if (hostname === '127.0.0.1') return true;
  if (hostname === '::1') return true;
  if (hostname === '0.0.0.0') return true;
  
  // IPv4 private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
  if (/^10\./.test(hostname)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;
  if (/^192\.168\./.test(hostname)) return true;
  
  return false;
}

export async function loadConfig(configPath: string): Promise<ParsedConfig> {
  const raw = fs.readFileSync(configPath, 'utf-8');
  const config = yaml.load(raw) as KeyholeConfig;
  validateConfig(config);
  
  const domainToService = new Map<string, string>();
  const secretRefs: string[] = [];
  
  for (const [name, service] of Object.entries(config.services)) {
    for (const domain of service.domains) {
      const host = typeof domain === 'string' ? domain : domain.host;
      if (typeof domain === 'string') {
        if (domainToService.has(domain)) {
          throw new Error(
            `Domain "${domain}" mapped to both "${domainToService.get(domain)}" and "${name}"`
          );
        }
        domainToService.set(domain, name);
      }
    }
    
    // Derive base_url from first domain if not set explicitly.
    // Use http:// for local/private hosts, https:// for everything else.
    if (!service.base_url) {
      const firstDomain = service.domains[0];
      const host = typeof firstDomain === 'string' ? firstDomain : firstDomain.host;
      const protocol = isLocalHost(host) ? 'http' : 'https';
      service.base_url = `${protocol}://${host}`;
    }
    
    secretRefs.push(service.auth.secret_ref);
  }
  
  return { ...config, _domainToService: domainToService, _secretRefs: [...new Set(secretRefs)] };
}

function validateConfig(config: KeyholeConfig): void {
  if (!config.services || typeof config.services !== 'object') {
    throw new Error('keyhole.yaml must have a "services" section');
  }
  
  for (const [name, service] of Object.entries(config.services)) {
    if (!service.domains?.length) {
      throw new Error(`Service "${name}" must have at least one domain`);
    }
    if (!service.auth?.type || !service.auth?.secret_ref) {
      throw new Error(`Service "${name}" must have auth.type and auth.secret_ref`);
    }
    
    const validAuthTypes = ['bearer', 'basic', 'query_param', 'custom_header'];
    if (!validAuthTypes.includes(service.auth.type)) {
      throw new Error(`Service "${name}" has invalid auth.type "${service.auth.type}"`);
    }
    
    if (service.auth.type === 'query_param' && !service.auth.param_name) {
      throw new Error(`Service "${name}" with query_param auth requires param_name`);
    }
    if (service.auth.type === 'custom_header' && !service.auth.header_name) {
      throw new Error(`Service "${name}" with custom_header auth requires header_name`);
    }
    
    // Validate explicit base_url protocol
    if (service.base_url) {
      if (!service.base_url.startsWith('http://') && !service.base_url.startsWith('https://')) {
        throw new Error(
          `Service "${name}" has invalid base_url: "${service.base_url}" – ` +
          `must start with http:// or https://`
        );
      }
    }
    
    // Validate streaming_window_cap
    if (service.response_masking?.streaming_window_cap !== undefined) {
      const cap = service.response_masking.streaming_window_cap;
      if (typeof cap !== 'number' || cap < 1 || !Number.isInteger(cap)) {
        throw new Error(
          `Service "${name}" has invalid streaming_window_cap: must be a positive integer`
        );
      }
    }
    
    // Validate and warn about regex patterns
    if (service.response_masking?.patterns) {
      const streaming = service.response_masking.streaming || 'stream';
      const windowCap = service.response_masking.streaming_window_cap ?? 200;
      for (const pattern of service.response_masking.patterns) {
        try { new RegExp(pattern); } catch (e) {
          throw new Error(`Service "${name}" has invalid regex: "${pattern}" – ${e.message}`);
        }
        if (streaming === 'stream' && /[+*]/.test(pattern) && !/\{\d+\}/.test(pattern)) {
          console.warn(
            `[keyhole] Warning: Service "${name}" has unbounded pattern "${pattern}" ` +
            `in streaming mode (window cap: ${windowCap}). Consider increasing ` +
            `streaming_window_cap, using "streaming: buffer", or bounded quantifiers.`
          );
        }
      }
    }
    
    // Validate json_paths syntax
    if (service.response_masking?.json_paths) {
      for (const jp of service.response_masking.json_paths) {
        if (!jp.startsWith('$')) {
          throw new Error(
            `Service "${name}" has invalid json_path: "${jp}" – must start with "$"`
          );
        }
      }
    }
    
    if (service.sdk_env) {
      for (const [envVar, template] of Object.entries(service.sdk_env)) {
        if (template.includes('{{') && !template.includes('{{placeholder}}')) {
          throw new Error(`Service "${name}" sdk_env.${envVar}: only {{placeholder}} supported`);
        }
      }
    }
  }
  
  if (config.agents) {
    const serviceNames = new Set(Object.keys(config.services));
    for (const [agentName, agent] of Object.entries(config.agents)) {
      for (const svc of agent.services) {
        if (!serviceNames.has(svc)) {
          throw new Error(`Agent "${agentName}" references unknown service "${svc}"`);
        }
      }
    }
  }
}
```

---

## 12. CLI

### 12.1 Entry Point

```
npx keyhole <command> [options]

Commands:
  init                    Create a keyhole.yaml config file
  add <service>           Store a secret in the OS keychain
  remove <service>        Remove a secret from the OS keychain
  list                    List configured services and secret status
  test [service]          Test connectivity through the sidecar
  vault create            Create an encrypted vault file
  vault add <service>     Add/update a secret in the vault
  vault remove <service>  Remove a secret from the vault
  vault list              List secrets in the vault (names only)
  help                    Show help
  version                 Show version
```

### 12.2 `keyhole init`

Creates a `keyhole.yaml` with example configuration.

```
$ npx keyhole init

✔ Created keyhole.yaml with example configuration
  Edit the file to add your services, then run:
  npx keyhole add <service-name>
```

### 12.3 `keyhole add <service>`

```
$ npx keyhole add github

Service: github
Secret ref: github-token (from keyhole.yaml)
Enter secret value: •••••••••••••••••••

✔ Stored "github-token" in OS keychain
✔ Verified: secret is retrievable
```

### 12.4 `keyhole remove <service>`

```
$ npx keyhole remove github

Remove "github-token" from OS keychain? (y/N): y
✔ Removed "github-token" from OS keychain
```

### 12.5 `keyhole list`

```
$ npx keyhole list

Services configured in keyhole.yaml:

  github       api.github.com          bearer    ✔ stored
  openai       api.openai.com          bearer    ✗ not found
  gemini       generativelanguage...   query     ✔ stored

2 of 3 services have secrets configured.
Run "npx keyhole add openai" to add the missing secret.
```

### 12.6 `keyhole test [service]`

```
$ npx keyhole test

Starting sidecar...
✔ Sidecar ready (PID 12345)

Testing github...  → GET /user → 200 OK ✔
Testing openai...  → GET /v1/models → 200 OK ✔
Testing gemini...  → GET /v1/models → 200 OK ✔

All 3 services operational.
```

### 12.7 `keyhole vault create`

```
$ npx keyhole vault create

Enter master passphrase: ••••••••••••
Confirm master passphrase: ••••••••••••

✔ Vault created at .keyhole.vault (permissions: 0600)
  To add secrets: npx keyhole vault add <service-name>
```

### 12.8 `keyhole vault add <service>`

```
$ npx keyhole vault add github

Enter master passphrase: ••••••••••••
✔ Vault unlocked

Service: github
Secret ref: github-token (from keyhole.yaml)
Enter secret value: •••••••••••••••••••

✔ Secret "github-token" stored in vault
✔ Vault re-encrypted and saved
```

### 12.9 `keyhole vault remove <service>`

```
$ npx keyhole vault remove github

Enter master passphrase: ••••••••••••
Remove "github-token" from vault? (y/N): y

✔ Removed "github-token" from vault
```

### 12.10 `keyhole vault list`

```
$ npx keyhole vault list

Enter master passphrase: ••••••••••••

Secrets in vault:
  github-token
  openai-api-key
  gemini-api-key

3 secrets stored.
Missing: stripe-secret-key (service "stripe" configured but not in vault)
```

### 12.11 CLI Implementation Notes

- CLI reads `keyhole.yaml` from CWD by default; override with `--config <path>`
- Secret input uses `readline` with `{ terminal: true }` to hide input
- All CLI output goes to stderr (stdout can be piped)
- Exit codes: 0 = success, 1 = error, 2 = partial success
- Vault passphrase minimum: 12 characters

---

## 13. Public API

```typescript
// src/index.ts

export interface KeyholeOptions {
  /** Path to keyhole.yaml. Default: './keyhole.yaml' */
  config?: string;
  
  /** Patch http/https/fetch for transparent interception. Default: false */
  autoPatch?: boolean;
  
  /** Secret store to use. Default: auto-detect (keychain → vault) */
  store?: 'keychain' | 'vault';
  
  /** Path to vault file. Default: '.keyhole.vault' */
  vaultPath?: string;
  
  /** Vault passphrase. If not provided with vault store, enters PENDING_UNLOCK. */
  vaultPassphrase?: string;
  
  /** Agent identity for multi-agent mode. */
  agent?: string;
  
  /** Request timeout in milliseconds. Default: 30000 */
  timeout?: number;
  
  /** Auto-restart sidecar on crash. Default: false */
  autoRestart?: boolean;
}

export interface Keyhole {
  createClient(serviceName: string): KeyholeClient;
  getSafeEnv(): Record<string, string>;
  getSafeEnv(serviceName: string): Record<string, string>;
  installInterceptor(): void;
  uninstallInterceptor(): void;
  unlock(passphrase: string): Promise<void>;
  readonly state: 'ready' | 'pending_unlock' | 'error';
  shutdown(): Promise<void>;
  on(event: 'error', listener: (err: Error) => void): void;
  on(event: 'redaction', listener: (info: RedactionEvent) => void): void;
  on(event: 'restarted', listener: () => void): void;
  on(event: 'unlocked', listener: () => void): void;
}

export interface RedactionEvent {
  service: string;
  path: string;
  layer: 'header' | 'known_secret' | 'pattern' | 'json_path';
  count: number;
}

export async function createKeyhole(options?: KeyholeOptions): Promise<Keyhole>;
```

---

## 14. Multi-Agent Support

### 14.1 Config

```yaml
agents:
  content-bot:
    services: [github, openai, anthropic]
  deploy-bot:
    services: [github, stripe]
```

### 14.2 Implementation

When `createKeyhole({ agent: 'content-bot' })` is called:
1. Parent generates OTT for this agent
2. Sidecar registers: `OTT-abc → agent: content-bot → services: [github, openai, anthropic]`
3. Request with OTT-abc for "stripe" → rejected

If no `agents` section in config, all services available to any OTT.

---

## 15. Moltbot Integration

### 15.1 Gateway Integration

```typescript
import { createKeyhole } from 'agent-keyhole';

const keyhole = await createKeyhole({
  config: './keyhole.yaml',
  autoPatch: true
});

const safeEnv = keyhole.getSafeEnv();

// Replace real keys in moltbot.json with placeholders
for (const [skillName, skillConfig] of Object.entries(moltbotConfig.skills.entries)) {
  if (skillConfig.env) {
    for (const [envVar] of Object.entries(skillConfig.env)) {
      if (safeEnv[envVar]) skillConfig.env[envVar] = safeEnv[envVar];
    }
  }
}

// Skills work as before – interceptor catches all outbound HTTP
```

### 15.2 New Skill Development

```typescript
export default async function(ctx) {
  const github = ctx.keyhole.createClient('github');
  const issues = await github('/repos/owner/repo/issues', { method: 'GET' });
  return issues.json();
}
```

### 15.3 VPS Deployment

```typescript
// Boot with vault
const keyhole = await createKeyhole({
  config: './keyhole.yaml',
  store: 'vault',
  autoPatch: true,
  vaultPassphrase: readPassphraseFromSecureSource(),
});

// Or boot without passphrase, unlock later
const keyhole = await createKeyhole({
  config: './keyhole.yaml',
  store: 'vault',
  autoPatch: true,
});
// Sends webhook alert, waits for unlock
await keyhole.unlock(passphraseFromOperator);
```

---

## 16. Error Handling

### 16.1 Error Categories

| Error | Response to Agent | Logged |
|---|---|---|
| Unknown service | `{ error: "Unknown service: foo" }` | Yes |
| Missing secret at boot | Sidecar fails to start (keychain) or PENDING_UNLOCK (vault) | Yes |
| OTT mismatch | `{ error: "Invalid authentication token" }`, conn closed | Yes (warn) |
| Agent not authorized | `{ error: "Agent not authorized for service" }` | Yes (warn) |
| Vault locked | `{ error: "Vault is locked – passphrase required" }` | Yes |
| Vault wrong passphrase | Error returned, remains in PENDING_UNLOCK | Yes (warn) |
| Upstream timeout | `{ status: 504, error: "Upstream timeout" }` | Yes |
| Upstream error | Status + masked body forwarded | Yes |
| IPC failure | Error thrown in client | Yes |
| IPC malformed JSON | Logged and skipped, connection kept alive | Yes (warn) |
| IPC connection lost | Auto-reconnect attempted (3 retries), then error | Yes |
| Config invalid | `createKeyhole()` throws | Yes |
| Keychain unavailable | Error with guidance to install or use vault | Yes (error) |
| Response accumulator overflow | L4 skipped, warning logged, L2/L3 still applied | Yes (warn) |

### 16.2 Health Check

```typescript
// Request
{ service: '__health__', method: 'GET', path: '/' }

// Response (ready)
{ status: 200, body: '{"state":"ready","uptime":12345}' }

// Response (locked)
{ status: 503, body: '{"state":"pending_unlock","message":"Vault is locked"}' }
```

---

## 17. Audit Logging

### 17.1 Log Format

JSON objects written to configured output (default: stderr).

```typescript
interface AuditLogEntry {
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  event: string;
  service?: string;
  method?: string;
  path?: string;           // Sanitized – no secret query params
  status?: number;
  duration_ms?: number;
  redacted?: boolean;
  redaction_count?: number;
  redaction_layers?: string[];
  agent?: string;
  error?: string;
}
```

### 17.2 Log Events

| Event | Level | When |
|---|---|---|
| `sidecar.boot` | info | Sidecar started |
| `sidecar.ready` | info | Socket listening, ready |
| `sidecar.shutdown` | info | Clean shutdown |
| `request.proxied` | info | Request proxied successfully |
| `request.rejected` | warn | Unknown service, bad OTT, unauthorized |
| `request.malformed` | warn | IPC message failed JSON parse |
| `request.failed` | error | Upstream request failed |
| `response.redacted` | warn | Masking was applied |
| `response.accumulator_overflow` | warn | L4 JSON path accumulator exceeded limit |
| `secret.resolved` | debug | Secret read from store |
| `secret.missing` | error | Required secret not found |
| `vault.pending_unlock` | warn | Entered PENDING_UNLOCK |
| `vault.unlocked` | info | Vault unlocked successfully |
| `vault.unlock_failed` | error | Wrong passphrase |
| `redirect.untrusted` | warn | Credentials stripped on redirect |
| `redirect.reinjected` | info | Credentials re-injected on return to trusted domain |
| `alert.sent` | info | Webhook alert sent |
| `alert.failed` | error | Webhook alert failed |
| `ipc.reconnect` | warn | Client reconnecting after disconnect |
| `ipc.reconnect_failed` | error | All reconnect attempts exhausted |

### 17.3 What Is NEVER Logged

- Secret values (real or placeholder)
- Full request/response bodies (unless `verbose: true`, post-masking only)
- OTT values
- Socket paths (beyond initial boot log)

**Path sanitization:** For `query_param` auth, the secret parameter is stripped before logging:

```typescript
function sanitizePathForLog(path: string, service: ServiceConfig): string {
  if (service.auth.type === 'query_param') {
    try {
      const url = new URL('http://dummy' + path);
      url.searchParams.delete(service.auth.param_name);
      const cleaned = url.pathname + url.search;
      return cleaned.endsWith('?') ? cleaned.slice(0, -1) : cleaned;
    } catch {
      return path.split('?')[0] + '?[query redacted]';
    }
  }
  return path;
}
```

---

## 18. Project Structure

```
agent-keyhole/
├── src/
│   ├── index.ts                    # Public API: createKeyhole(), types
│   ├── sidecar/
│   │   ├── process.ts              # Child process entry point
│   │   ├── ipc-server.ts           # Unix socket server, OTT validation
│   │   ├── request-builder.ts      # Auth injection, redirect handling
│   │   ├── response-masker.ts      # 4-layer masking + streaming buffer
│   │   ├── json-path-redactor.ts   # JSON path parsing and redaction
│   │   ├── audit-logger.ts         # JSON audit logging
│   │   └── alerting.ts             # Webhook alerts for VPS boot failures
│   ├── client/
│   │   ├── spawn.ts                # Spawns sidecar, OTT generation, crash recovery
│   │   ├── ipc-client.ts           # Socket client, request correlation, reconnect
│   │   ├── interceptor.ts          # Patches http/https/fetch
│   │   ├── binary-detect.ts        # Shared binary content detection utility
│   │   ├── fake-request.ts         # http.ClientRequest compatibility shim (Writable)
│   │   ├── create-client.ts        # fetch-like client factory
│   │   └── safe-env.ts             # Placeholder env var generator
│   ├── store/
│   │   ├── interface.ts            # SecretStore interface
│   │   ├── keychain.ts             # OS keychain (macOS/Linux)
│   │   └── vault.ts                # Encrypted file store (AES-256-GCM)
│   ├── config/
│   │   ├── loader.ts               # YAML loading + validation
│   │   └── schema.ts               # TypeScript type definitions
│   └── cli/
│       ├── index.ts                # CLI entry point, command routing
│       ├── init.ts                 # Creates keyhole.yaml
│       ├── add.ts                  # Stores secret in keychain
│       ├── remove.ts               # Removes from keychain
│       ├── list.ts                 # Lists services + status
│       ├── test.ts                 # Tests connectivity
│       └── vault.ts                # Vault subcommands
├── templates/
│   └── keyhole.yaml.template
├── bin/
│   └── keyhole.js                  # #!/usr/bin/env node CLI shim
├── tsconfig.json
├── package.json
├── LICENSE
├── README.md
└── .gitignore
```

---

## 19. Build & Distribution

### 19.1 package.json

```json
{
  "name": "agent-keyhole",
  "version": "1.0.0",
  "description": "A trust boundary for LLM agents. Your agent never holds your real credentials.",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "bin": { "keyhole": "bin/keyhole.js" },
  "files": ["dist/", "bin/", "templates/"],
  "os": ["darwin", "linux"],
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "test": "node --test",
    "lint": "tsc --noEmit",
    "prepublishOnly": "npm run build"
  },
  "dependencies": {
    "js-yaml": "^4.1.0"
  },
  "devDependencies": {
    "@types/js-yaml": "^4.0.9",
    "@types/node": "^20.0.0",
    "typescript": "^5.5.0"
  },
  "engines": { "node": ">=18.0.0" },
  "keywords": [
    "agent", "llm", "security", "credentials", "proxy",
    "sidecar", "trust-boundary", "mcp", "ai-agent"
  ],
  "license": "MIT"
}
```

### 19.2 TypeScript Configuration

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

---

## 20. Testing Strategy

### 20.1 Unit Tests

Using Node.js built-in test runner (`node --test`).

| Module | What to test |
|---|---|
| `config/loader.ts` | Valid YAML, all validation errors, domain uniqueness, agent refs, json_paths validation, streaming_window_cap validation, base_url protocol validation, auto-derived protocol (localhost=http, remote=https) |
| `store/keychain.ts` | Mock `execFileSync` per platform, missing keychain errors |
| `store/vault.ts` | Create, unlock correct/wrong passphrase, add/remove/list, corrupt file, permissions |
| `sidecar/request-builder.ts` | All 4 auth types, header construction, URL building, query param injection, binary body decoding from Base64, buildAuthHeaders() for re-injection, injectQueryParamAuth() for re-injection |
| `sidecar/response-masker.ts` | L1 header scrub, L2 exact match (plain/base64/URL-encoded), L3 patterns, L4 json_paths (simple, nested, wildcard, non-JSON body, non-string values), combined pipeline, min length threshold, placeholder exclusion, binary detection + sniffing |
| `sidecar/response-masker.ts` (streaming) | Secret split across chunks, secret at boundary, small chunks, flush, regex window sizing, custom streaming_window_cap, L4 deferred to flush, accumulator overflow (>10MB → L4 skipped, memory freed) |
| `sidecar/json-path-redactor.ts` | Path parsing ($.a.b, $[*].c, $.a[0].b), nested redaction, missing paths, non-object targets, array wildcards, non-string leaf values (skipped) |
| `sidecar/ipc-server.ts` | Malformed JSON handling (no crash, logged, skipped), valid framing after malformed message |
| `client/binary-detect.ts` | Text Content-Types → false, binary Content-Types → true, no Content-Type + Buffer with null bytes → true, string body → always false, byte sniffing edge cases |
| `client/safe-env.ts` | Placeholder generation, template resolution |
| `client/ipc-client.ts` | Length-prefix framing, concurrent requests, timeout, updateConnection, transient disconnect reconnect (success and exhaustion), intentional disconnect (no reconnect) |
| `client/fake-request.ts` | write(), end(), _write() via pipe, _final() IPC send with UTF-8 text body, _final() IPC send with Base64 binary body, destroy()/abort() cleanup, body size enforcement via both write() and _write() |
| `client/create-client.ts` | Request/response mapping, error propagation |
| `cli/*` | Each command's output and error handling (mocked keychain) |

### 20.2 Integration Tests

| Scenario | What it proves |
|---|---|
| **Full roundtrip (mock upstream)** | Spawn → IPC → sidecar → mock API → masked response |
| **Binary request roundtrip (http.request)** | Image upload via FakeClientRequest → Base64 IPC → sidecar decodes → upstream receives intact binary |
| **Binary request roundtrip (fetch)** | Binary body via intercepted fetch → Base64 IPC → sidecar decodes → upstream receives intact binary |
| **Binary response roundtrip** | Upstream returns image → Base64 IPC → client decodes → binary intact |
| **Interceptor roundtrip** | `autoPatch` → `fetch(github)` → intercepted → correct response |
| **Local service (http://)** | Service with `localhost` domain → derived `http://` base URL → request succeeds |
| **Explicit base_url** | Service with `base_url: "http://internal:8080"` → used as-is |
| **Path-prefix routing** | Two services, same domain, different prefixes → correct secret |
| **Multi-agent isolation** | Agent A → github ✓, Agent B → github ✗ |
| **OTT validation** | Wrong OTT → rejected |
| **Malformed IPC message** | Invalid JSON → logged, skipped, connection alive for next message |
| **Streaming masking** | Secret split across chunks → fully masked |
| **Streaming regex** | Pattern split at boundary → caught by window |
| **Streaming custom window cap** | Long token with `streaming_window_cap: 600` → caught |
| **Streaming accumulator overflow** | Mock 15MB JSON response with json_paths → L4 skipped, L2/L3 applied, warning logged, no OOM |
| **JSON path redaction** | `$.token` in response → redacted |
| **JSON path nested** | `$.credentials.access_token` → redacted |
| **JSON path wildcard** | `$.data[*].secret` with array → all elements redacted |
| **JSON path non-JSON** | Plain text response + json_paths config → no crash, no redaction |
| **Streaming JSON path** | Streamed JSON response under 10MB → L4 applied at flush |
| **Placeholder non-redaction** | Echo "KEYHOLE_MANAGED" → NOT redacted |
| **Sidecar crash recovery** | Kill sidecar → error event → pending requests fail → named function restarts |
| **IPC transient disconnect** | Socket drops → auto-reconnect → subsequent requests succeed |
| **IPC reconnect exhaustion** | Socket drops, sidecar gone → 3 retries → all pending fail |
| **Pipe to FakeClientRequest** | `readableStream.pipe(fakeRequest)` → body sent correctly |
| **FakeClientRequest destroy** | `req.destroy()` → resources cleaned, no IPC send |
| **Config validation** | Bad YAML → clear error at startup |
| **Config streaming_window_cap** | Invalid value → error; valid value → used in window sizing |
| **Config base_url validation** | `base_url: "ftp://foo"` → error |
| **Body size limit (client)** | FakeClientRequest rejects during .write() |
| **Body size limit (pipe)** | FakeClientRequest rejects during _write() via pipe |
| **Body size limit (fetch)** | routeFetchThroughSidecar rejects before IPC |
| **macOS keychain access** | Store + retrieve with `-T` flags → no GUI prompt |
| **Audit log sanitization** | `query_param` → logged path has no secret |
| **IPC length overflow** | 0xFFFFFFFF prefix → connection destroyed |
| **OTT sync on restart** | Kill + autoRestart → new OTT → requests succeed |
| **Binary sniffing** | Missing Content-Type + binary body → treated as binary |
| **Unbounded pattern warning** | `.*` pattern in streaming mode → warning with cap value |
| **Redirect credential strip** | 302 to untrusted domain → auth removed |
| **Redirect credential re-injection** | trusted → untrusted → trusted → auth re-injected on final hop |
| **Redirect chain (query_param)** | trusted (with ?key=secret) → untrusted (key stripped) → trusted (key re-injected) |
| **Zombie socket cleanup** | Orphan socket → start → cleaned up |
| **Vault roundtrip** | Create → add secrets → boot with vault → proxy works |
| **Vault PENDING_UNLOCK** | No passphrase → pending → rejected → unlock → works |
| **Vault wrong passphrase** | Wrong → error → correct → works |
| **Boot alert webhook** | PENDING_UNLOCK + webhook → POST sent |
| **Health endpoint states** | ready=200, pending_unlock=503 |

### 20.3 Manual Test Checklist

- [ ] `npx keyhole init` creates valid YAML
- [ ] `npx keyhole add github` stores in macOS/Linux keychain
- [ ] `npx keyhole list` shows correct status
- [ ] `npx keyhole test` makes real API calls
- [ ] OpenAI SDK works with autoPatch + placeholder
- [ ] Anthropic SDK works with autoPatch + placeholder
- [ ] GitHub Octokit works with autoPatch + placeholder
- [ ] Agent dumping `process.env` only sees placeholders
- [ ] Response echoing credentials is redacted
- [ ] Response with `json_paths` target fields → redacted
- [ ] Binary file upload via http.request → arrives intact
- [ ] Local service on `http://localhost:PORT` → works without explicit base_url
- [ ] `npx keyhole vault create` creates encrypted file (0600)
- [ ] `npx keyhole vault add/list` work correctly
- [ ] Sidecar with vault + passphrase → operational
- [ ] Sidecar with vault, no passphrase → PENDING_UNLOCK
- [ ] `keyhole.unlock()` transitions to READY
- [ ] Webhook fires on PENDING_UNLOCK
- [ ] Health check returns correct state
- [ ] IPC client recovers from transient socket disconnect
- [ ] `readable.pipe(fakeRequest)` works end-to-end
- [ ] Sidecar crash + autoRestart → recovers without `arguments.callee` error

---

## 21. Security Considerations

### 21.1 What Keyhole Guarantees

1. **No real credentials in agent process memory.**
2. **No real credentials on disk in plaintext.** No `.env` files, no env vars, no unencrypted config.
3. **No credentials in responses.** All responses masked before reaching agent.
4. **Process-level isolation.** Sidecar is a separate OS process.
5. **Socket-level access control.** Unix sockets with 0600 permissions.
6. **Request-level authentication.** OTT on every IPC message.
7. **Encrypted-at-rest for VPS.** AES-256-GCM vault with scrypt key derivation.
8. **Redirect-safe.** Credentials stripped when APIs redirect to untrusted domains, re-injected when returning to trusted domains.
9. **Binary-safe IPC.** Binary request and response bodies are Base64-encoded, preventing data corruption.

### 21.2 Known Limitations

1. **Agent can use the sidecar.** It can make authorized calls – Policy Engine (v1.5) mitigates.
2. **Not a network firewall.** Agent can send non-secret data anywhere.
3. **Short secrets (<8 chars).** Not scanned in responses to avoid false positives.
4. **Binary responses.** Only Layer 1 (headers) applied.
5. **Timing side-channels.** Intercepted vs non-intercepted timing differs.
6. **Process table.** Sidecar process visible in `ps` (no secrets in args).
7. **Direct undici imports.** `import { fetch } from 'undici'` bypasses interception. Use `createClient` instead.
8. **10MB body limit.** Large uploads rejected in v1. IPC streaming in v1.5.
9. **VPS reboot requires human.** Vault store needs passphrase – by design.
10. **V8 string immutability.** Passphrase clearing is best-effort. The original string remains in V8's managed heap until garbage collection. See section 3.3 for details and the v1.5 `Buffer`-based hardening plan.
11. **FakeClientRequest is not a full http.ClientRequest.** SDKs that access the raw `socket` property or rely on TLS-specific events will not work with `autoPatch`. Use `createClient()` for these cases.
12. **Streaming JSON path redaction is deferred.** Layer 4 (json_paths) requires a complete JSON document and cannot operate on partial chunks. In streaming mode, it is applied at flush time on the full accumulated buffer. If the accumulated response exceeds 10MB, Layer 4 is skipped to prevent OOM. For NDJSON or very large JSON streams, use `streaming: buffer` or rely on Layers 2 and 3.
13. **No Windows support.** v1 targets macOS and Linux only. Windows support adds significant complexity (Named Pipes, PowerShell Credential Manager, `cmdkey` length limits, platform-specific `chmod` behavior) with limited demand in the AI agent development community.

### 21.3 Attack Scenarios

| Attack | Mitigation |
|---|---|
| Agent reads `process.env` | Only placeholder values |
| Agent reads filesystem | Secrets in keychain/vault, not files |
| Agent discovers socket path | 0600 permissions + OTT required |
| Agent spawns child to probe socket | Child doesn't have OTT |
| Agent triggers echo of auth header | Response masker L2 redacts |
| API returns new credential | Response masker L3 pattern catches |
| API returns credential in known JSON field | Response masker L4 json_path catches |
| API redirects to untrusted domain | `redirect: 'manual'`, credentials stripped |
| API redirects untrusted → back to trusted | Credentials re-injected correctly |
| Agent uploads binary with injected secret bytes | Base64 encoding preserves exact bytes, no corruption-based bypass |
| Crafted IPC length prefix (DoS) | Max size check, connection destroyed |
| Malformed IPC JSON payload | Caught by try/catch, logged, skipped — sidecar stays alive |
| Large API response (OOM attack on sidecar) | 10MB accumulator cap, L4 gracefully skipped |
| Agent social-engineers user | Out of scope – technical boundary only |

---

## 22. Future Scope (Not v1)

### 22.1 v1.5: Policy Engine
Method/path allow-deny per service per agent. Architecture hook: single function between 
OTT validation and request building.

### 22.2 v1.5: Request Body Inspection
Detect exfiltration via request bodies. Hook: request builder has full body.

### 22.3 v1.5: Rate Limiting
Per-agent per-service token bucket. Hook: sidecar tracks per-request metadata.

### 22.4 v1.5: Additional Secret Stores
HashiCorp Vault, AWS Secrets Manager, Google Secret Manager, 1Password CLI. Hook: 
`SecretStore` interface.

### 22.5 v1.5: IPC Streaming
Chunked transfer over unix socket with backpressure for large uploads. Removes 10MB limit.

### 22.6 v1.5: Buffer-Based Passphrase Handling
Pass vault passphrase as `Buffer` instead of `string` to enable deterministic memory
zeroing via `buffer.fill(0)`. Requires updating scrypt and vault unlock interfaces to
accept `Buffer` input.

### 22.7 v2: Windows Support
Named Pipes, PowerShell Credential Manager / `cmdkey`, platform-specific IPC and 
permissions handling.

### 22.8 v2: Web3 / Crypto Wallet Signing
Sidecar holds private keys, exposes "sign transaction" endpoint. Agent only sees tx hashes.

### 22.9 v2: MCP Server Mode
Expose Keyhole as MCP server for agent tool discovery.

---

## 23. Build Phases

### Phase 1: Foundation
**Goal:** Secret from keychain/vault, sidecar IPC works.  
**~500 LOC**
- `src/store/interface.ts`, `keychain.ts`, `vault.ts`
- `src/config/schema.ts`, `loader.ts`
- `src/sidecar/process.ts`, `ipc-server.ts`, `alerting.ts`
- `src/client/spawn.ts`, `ipc-client.ts`

**Milestone:** Spawn sidecar → IPC message → secret resolved → response. PENDING_UNLOCK works.

### Phase 2: Request Proxying
**Goal:** Full roundtrip through real API, including binary bodies.  
**~350 LOC**
- `src/sidecar/request-builder.ts`
- `src/client/create-client.ts`
- `src/client/binary-detect.ts`

**Milestone:** `createClient('github')('/user')` returns authenticated response. Binary uploads arrive intact.

### Phase 3: HTTP Interception
**Goal:** Transparent interception, existing SDKs work.  
**~400 LOC**
- `src/client/interceptor.ts`, `fake-request.ts`, `safe-env.ts`

**Milestone:** `fetch('https://api.github.com/user')` with autoPatch works. `process.env` shows placeholder. Binary uploads via `http.request` work.

### Phase 4: Response Masking
**Goal:** No credential material reaches agent.  
**~450 LOC**
- `src/sidecar/response-masker.ts`, `json-path-redactor.ts`, `audit-logger.ts`

**Milestone:** Echo API → redacted. Streamed split secret → masked. JSON path fields → redacted. Accumulator overflow → L4 skipped gracefully.

### Phase 5: CLI
**Goal:** Complete setup and management experience.  
**~400 LOC**
- `src/cli/*`, `bin/keyhole.js`, `templates/`

**Milestone:** Full `init → add → list → test` and `vault create → add → list` workflows.

### Phase 6: Multi-Agent & Polish
**Goal:** Access control, docs, publish.  
**~200 LOC**
- Updates to `ipc-server.ts`, `spawn.ts`, `index.ts`
- `README.md`

**Milestone:** Multi-agent works. Package published on npm.

---

### Total Estimated LOC: ~2,300
### Total Runtime Dependencies: 1 (js-yaml)
### Total Files: ~29