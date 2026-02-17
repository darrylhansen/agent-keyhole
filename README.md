# Agent-Keyhole

**A trust boundary for LLM agents. Your agent never holds your real credentials.**

Agent-Keyhole runs a trusted sidecar process that holds your real API keys (from OS keychain or encrypted vault) while your agent process only sees dummy placeholders. All upstream responses are automatically scrubbed so credentials never leak back to the agent, even if the API echoes them.

## Quick Start

```bash
npm install agent-keyhole
npx keyhole init
npx keyhole add github   # stores your token in OS keychain
```

```typescript
import { createKeyhole } from 'agent-keyhole';

const kh = await createKeyhole();
const github = kh.createClient('github');

const res = await github('/repos/octocat/hello-world');
const repo = await res.json();
// Your real token was injected by the sidecar.
// The agent process never saw it.

await kh.shutdown();
```

## How It Works

```
AGENT PROCESS (untrusted)           KEYHOLE SIDECAR (trusted)
├── HTTP Interceptor                ├── Secret Store (keychain or vault)
│   patches http/https/fetch        ├── Request Builder (injects real creds)
├── Keyhole Client                  ├── Response Masker (4-layer redaction)
│   fetch-like per-service API      ├── Audit Logger
└── IPC Client ──── Unix Socket ──→ └── OTT Authentication
```

The sidecar is a separate OS process. Memory isolation is enforced even if the agent runs arbitrary code. Communication uses Unix domain sockets (0600 permissions) with a one-time token on every request.

**Response masking is zero-config.** The 4-layer pipeline:

1. **Header scrub** — strips `Authorization`, `Set-Cookie`, `X-API-Key`, etc.
2. **Known-secret scan** — detects your exact secrets (plain, base64, URL-encoded) via structural JSON walk or raw text fallback
3. **Heuristic engine** — catches *unknown* credentials (rotated keys, OAuth grants) using dual-signal detection: suspicious key name + high Shannon entropy
4. **User overrides** — optional regex patterns and JSON paths for edge cases

Layers 2 and 3 require no configuration. They work out of the box.

## Two Integration Modes

### `createClient()` — strongest isolation

The agent only sees a scoped fetch-like function. No URLs, no domains, no headers.

```typescript
const kh = await createKeyhole();
const github = kh.createClient('github');

const res = await github('/user/repos', {
  method: 'POST',
  body: JSON.stringify({ name: 'new-repo', private: true })
});
```

### `autoPatch` — transparent, for existing SDKs

Patches `http.request`, `https.request`, and `globalThis.fetch`. Existing code and SDKs work unchanged.

```typescript
const kh = await createKeyhole({ autoPatch: true });

// If you have a .env (post-migration): SDKs read placeholders automatically.
// If not: generate placeholder env vars from sdk_env mappings in keyhole.yaml:
// const env = kh.getSafeEnv();
// Object.assign(process.env, env);

const res = await fetch('https://api.github.com/user/repos');
// Real token injected by the sidecar — agent process never sees it.
```

## VPS / Headless Environments

On servers without an OS keychain, use the encrypted vault:

```bash
npx keyhole vault create          # AES-256-GCM with scrypt KDF
npx keyhole vault add github      # prompts for secret + passphrase
```

```typescript
const kh = await createKeyhole({
  store: 'vault',
  vaultPassphrase: process.env.VAULT_PASSPHRASE
});
```

If no passphrase is provided, the sidecar enters `PENDING_UNLOCK` state. Unlock at runtime:

```typescript
const kh = await createKeyhole({ store: 'vault' });
// kh.state === 'pending_unlock'
await kh.unlock(passphrase);
// kh.state === 'ready'
```

## Configuration

Services are defined in `keyhole.yaml`:

```yaml
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer             # bearer | basic | query_param | custom_header
      secret_ref: github-token
    headers:
      Accept: application/vnd.github+json
```

### After migration (most users)

If you ran `npx keyhole migrate`, your `.env` already has placeholder values.
SDKs read these automatically — just configure service domains and auth in `keyhole.yaml`.
No `sdk_env` or `placeholder` fields needed.

### Programmatic setup (no .env file)

If you don't have a `.env` file, use `sdk_env` to generate placeholder env vars:

```yaml
    sdk_env:
      GITHUB_TOKEN: "{{placeholder}}"
```

```typescript
const kh = await createKeyhole({ autoPatch: true });
const env = kh.getSafeEnv();        // reads sdk_env mappings from yaml
Object.assign(process.env, env);    // SDKs see placeholder values
```

If an SDK validates key format (e.g., OpenAI checks for `sk-` prefix), set a format-aware placeholder:

```yaml
    placeholder: "sk-keyhole-000000000000000000000000000000000000000000000000"
```

Response masking is automatic. For edge cases, add optional overrides:

```yaml
    response_masking:
      patterns:
        - "ghp_[A-Za-z0-9_]{36}"
      json_paths:
        - "$.credentials.access_token"
      heuristic:
        enabled: true                    # default
        min_length: 16                   # default
        min_entropy: 3.5                 # default
        additional_key_names: [my_key]   # merged with built-in list
```

Multi-agent access control restricts which agents can reach which services:

```yaml
agents:
  content-bot:
    services: [github, openai]
  deploy-bot:
    services: [github]
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `npx keyhole init` | Create a `keyhole.yaml` config file |
| `npx keyhole add <service>` | Store a secret in the OS keychain |
| `npx keyhole remove <service>` | Remove a secret from the OS keychain |
| `npx keyhole list` | List configured services and secret status |
| `npx keyhole test [service]` | Test connectivity through the sidecar |
| `npx keyhole vault create` | Create an encrypted vault file |
| `npx keyhole vault add <service>` | Add/update a secret in the vault |
| `npx keyhole vault remove <service>` | Remove a secret from the vault |
| `npx keyhole vault list` | List secrets in the vault (names only) |

All commands accept `--config <path>` to specify a custom config file.

## Security Model

**What it protects against:**
- Agent code reading API keys from memory or environment variables
- Credential leakage via API response echo (tokens returned in JSON bodies)
- Accidental logging of secrets by agent frameworks
- Redirect-based credential exfiltration (credentials stripped on untrusted domains)

**What it does not protect against:**
- A compromised OS or root-level attacker (the sidecar runs as the same user)
- Exfiltration of data obtained *using* the credentials (Keyhole controls auth, not authorization)
- Side-channel attacks on the sidecar process memory

## License

MIT

## Links

- [GitHub](https://github.com/darrylhansen/agent-keyhole)
- [Technical Specification](https://github.com/darrylhansen/agent-keyhole/blob/master/agent-keyhole-technical-specification.md)
