# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agent-Keyhole is a credential firewall for LLM agents. It runs a trusted **sidecar process** that holds real API keys (from OS keychain or encrypted vault), while the untrusted **agent process** only sees dummy placeholders. Communication happens over Unix domain sockets with one-time token (OTT) authentication.

**Current state:** The architecture specification is complete (`agent-keyhole-technical-specification.md`, ~3500 lines). Directory structure exists but source files have not been implemented yet. Implementation follows 6 build phases defined in the spec.

## Build & Development Commands

These are the **planned** commands (not yet wired up — `tsconfig.json` and source files need to be created first):

```bash
npm run build           # tsc → compiles to dist/
npm run dev             # tsc --watch
npm run test            # node --test (Node.js built-in test runner)
npm run lint            # tsc --noEmit (type-check only)
```

- **Node.js 18+** required (for native `fetch` support)
- **Single production dependency:** `js-yaml`
- **TypeScript target:** ES2022, module: NodeNext
- **Package type:** CommonJS
- **Platforms:** macOS, Linux only (Windows planned for v2)

## Architecture

### Two-Process Model

```
AGENT PROCESS (untrusted)           KEYHOLE SIDECAR (trusted)
├── HTTP Interceptor                ├── Config Store (immutable after boot)
│   (patches http/https/fetch)      ├── Secret Store (keychain or vault)
├── Keyhole Client                  ├── OTT Registry
│   (fetch-like factory)            ├── Request Builder (auth injection)
└── IPC Client ──── Unix Socket ──→ ├── Response Masker (4-layer redaction)
                    (OTT auth)      ├── Audit Logger
                                    └── Alerting System
```

### Source Layout (src/)

| Directory | Purpose |
|-----------|---------|
| `src/sidecar/` | Trusted process: IPC server, request building, response masking, audit logging |
| `src/client/` | Agent-side: sidecar spawning, IPC client, HTTP interceptor, `createClient()`, safe env vars |
| `src/store/` | Secret storage: `SecretStore` interface with keychain and encrypted vault implementations |
| `src/config/` | YAML config loading and validation (`keyhole.yaml`) |
| `src/cli/` | CLI commands: init, add, remove, list, test, vault subcommands |
| `src/index.ts` | Public API entry point |

### Key Abstractions

- **SecretStore interface** (`store/interface.ts`): `get/set/delete/list/has` — implemented by `KeychainStore` (OS keychain via shell commands) and `VaultStore` (AES-256-GCM encrypted file with scrypt KDF)
- **IPC transport**: Length-prefix framing (`[4B length][JSON payload]`), request/response correlation via UUID v4
- **Response Masker**: 4 layers — L1: header scrubbing, L2: known-secret exact match, L3: regex patterns, L4: JSON path redaction
- **Request Builder**: Strips agent auth, injects real credentials (header/query/basic/custom), validates redirect domains
- **HTTP Interceptor**: Patches `http.request`, `https.request`, `globalThis.fetch`; routes keyhole-managed domains to sidecar, passes others through

### Security Model

- Agent process never has access to real credentials (only dummy placeholders)
- Sidecar is a separate OS process — memory isolation even if agent runs arbitrary code
- OTT authentication on every IPC request
- Unix socket with 0600 permissions
- Vault passphrase delivered via IPC bootstrap message (not env vars or CLI args)
- Response masking prevents credential "echo" leaks from APIs
- `createClient()` is strongest isolation (agent sees no URLs/domains/keys); HTTP interceptor with `autoPatch` is transparent but slightly weaker

### Configuration

Services are defined in `keyhole.yaml`:
```yaml
services:
  github:
    domain: api.github.com
    secret_ref: github-token
    auth_type: header          # header | query | basic | custom
    auth_header: Authorization
    auth_header_prefix: "Bearer "
    response_masking:
      patterns: [...]
      json_paths: [...]

agents:                        # optional multi-agent access control
  content-bot:
    services: [github, openai]
```

## Build Phases

Implementation should follow these phases (each builds on the previous):

1. **Foundation** (~500 LOC): Secret store + sidecar IPC + PENDING_UNLOCK state
2. **Request Proxying** (~350 LOC): Request builder + `createClient()` + binary body support
3. **HTTP Interception** (~400 LOC): Patch http/https/fetch + FakeClientRequest shim + safe env
4. **Response Masking** (~450 LOC): 4-layer redaction + streaming buffer support
5. **CLI** (~400 LOC): Full init/add/list/test/vault workflows
6. **Multi-Agent & Polish** (~200 LOC): OTT-based access control + docs

## Testing

Uses **Node.js built-in test runner** (`node --test`). Run a single test file:
```bash
node --test src/store/vault.test.ts
```

Integration tests cover full roundtrips with mock upstream APIs, binary uploads/responses, interceptor transparency, and multi-agent isolation.
