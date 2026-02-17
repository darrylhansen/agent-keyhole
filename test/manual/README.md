# Manual UX Validation Suite

Step-by-step playbook for validating the migration workflow, response masking
pipeline, and CLI error paths. A human runs each step and evaluates messaging,
formatting, and correctness.

**Prerequisites:**
- `npm run build` (compiles src/ to dist/)
- Node.js 18+

## Secret Detection — Skip Logic

Migration uses a **dual-signal heuristic** to classify entries. Both conditions
must be true for an entry to be flagged as a secret:

1. **Suspicious key name** — matches known patterns like `_TOKEN`, `_SECRET`,
   `_KEY`, `_PASSWORD`, `_API_KEY`, `_CONNECTION_STRING`, `_DSN`, or contains
   substrings like `token`, `secret`, `password`, `credential`, `auth`, etc.
2. **Suspicious value** — longer than 8 characters, not a boolean or number,
   not a URL without credentials, not a `${VAR}` placeholder, does not contain
   `KEYHOLE_MANAGED` (format-aware placeholders are also excluded).

Examples of entries that are **skipped** (not secrets):

| Key | Value | Reason |
|-----|-------|--------|
| `PORT` | `3000` | Key not suspicious + value is numeric |
| `NODE_ENV` | `production` | Key not suspicious |
| `DATABASE_URL` | `postgres://host/db` | Key doesn't match suffix patterns (`_URL` is not in the list) |
| `API_KEY` | `${OPENAI_API_KEY}` | Value is a `${VAR}` placeholder reference |
| `APP_NAME` | `"my-cool-app"` | Key not suspicious |

---

> **Important:** All commands below assume you are in `test/manual/` as your
> working directory. The migrate command scans `process.cwd()` for secret
> files, and resolves `--config` relative to cwd. If you run from a different
> directory, files won't be found.

```bash
# Start here for ALL sections:
cd test/manual
```

---

## Section A: Migration — .env

This tests the migration path (Mode A): secrets move from `.env` to the vault,
`.env` gets format-aware placeholders, and SDKs read placeholders from `.env`
directly. `sdk_env` in `keyhole.yaml` is NOT needed for this flow.

Validates the full migration workflow from a realistic `.env` file.

### Setup

```bash
# 1. Copy the sample .env INTO this directory (test/manual/)
cp fixtures/sample.env .env

# 2. Initialize keyhole config (creates keyhole.yaml + updates .gitignore)
npx keyhole init --config fixtures/sample-keyhole.yaml

# Verify .gitignore was updated:
cat .gitignore
# Should show "# Added by keyhole" section with .keyhole.*, .env, etc.

# 3. Store setup (choose one):

# Option 1: Vault (headless/WSL/VPS)
npx keyhole vault create --config fixtures/sample-keyhole.yaml
# (enter a passphrase of 12+ characters)

# Option 2: Keychain (macOS/Linux desktop)
# No setup needed — keychain is auto-detected
```

### Run

```bash
npx keyhole migrate --config fixtures/sample-keyhole.yaml
```

After migration completes, verify stored secrets:

```bash
npx keyhole list --config fixtures/sample-keyhole.yaml
```

### UX Checkpoints

1. **Discovery** — CLI reports scanning `.env`
2. **Detection table** — 4 secrets detected, 4 non-secrets skipped:
   - Secrets: `GITHUB_TOKEN`, `OPENAI_API_KEY`, `DB_CONNECTION_STRING`, `STRIPE_SECRET_KEY`
   - Skipped: `PORT` (key not suspicious + numeric), `NODE_ENV` (key not suspicious),
     `LOG_LEVEL` (key not suspicious), `APP_NAME` (key not suspicious)
3. **Service matching** — All 4 secrets show as unmatched (no active services in
   fresh config). Each gets a generated `secret_ref` name.
4. **Import prompts** — asked to confirm import for each secret (or batch)
5. **Cleanup options** — prompted with R/D/S choices per file
6. **Placeholder replacement** — after cleanup, `.env` has format-aware placeholders
   for secrets, original values for non-secrets. Quoting preserved (double-quoted stays
   double-quoted, single-quoted stays single-quoted, `export` prefix preserved)
7. **Placeholder format** — verify placeholder values are unique and prefix-appropriate:
   - `GITHUB_TOKEN` → starts with `ghp_` (extracted from original `ghp_a1b2...` value)
   - `OPENAI_API_KEY` → starts with `sk-proj-` (extracted from original)
   - `STRIPE_SECRET_KEY` → starts with `sk_test_`
   - `DB_CONNECTION_STRING` → `db-connection-string_KEYHOLE_MANAGED` (URL value has
     no `_`/`-` prefix in first 12 chars)
   - All placeholders contain `KEYHOLE_MANAGED` as a substring
8. **No backup created** — verify no `.env.bak` file exists (backups removed to
   prevent agents from reading plaintext secrets via `cat .env.bak`)
9. **Cleanup warning** — the R/D/S prompt shows a warning that secrets are safely
   stored and can be viewed with `npx keyhole list`
10. **Store verification via list**:
    ```bash
    npx keyhole list --config fixtures/sample-keyhole.yaml
    ```
    Verify:
    - No services listed (all commented out in fresh config)
    - "Additional secrets in store" section shows all 4: `github-token`,
      `openai-api-key`, `db-connection-string`, `stripe-secret-key`
    - Summary shows `0 of 0 services have secrets configured` and
      `4 additional secret(s) in store without a matching service`
11. **Vault verification** (alternative):
    ```bash
    npx keyhole vault list --config fixtures/sample-keyhole.yaml
    ```
    All 4 secret refs should be listed.
12. **Secret retrieval via get**:
    ```bash
    npx keyhole get github-token
    ```
    Verify: the actual secret value is printed to stdout (no extra formatting).
    Try a nonexistent ref:
    ```bash
    npx keyhole get nonexistent-ref
    ```
    Expected: `Error: secret "nonexistent-ref" not found in store.`
13. **Scaffolded service stubs** — open `fixtures/sample-keyhole.yaml` and verify:
    - Stubs appear inside `services:` block, before the commented examples
    - All stubs have `api.example.com` and TODO instructions
    - Stubs do NOT contain `sdk_env`
    - All 4 secrets are scaffolded: `github-token`, `openai-api-key`,
      `db-connection-string`, `stripe-secret-key`
    - `npx keyhole list` still works (commented stubs don't break parsing)

### Cleanup

```bash
rm -f .env .keyhole.vault
git checkout fixtures/sample-keyhole.yaml
```

---

## Section B: Migration — JSON (Azure-style)

Validates nested JSON parsing with `localsettings.json`-style files.

### Setup

```bash
# Copy into a discoverable filename (localsettings.json is in SUPPORTED_FILES)
cp fixtures/sample-settings.json localsettings.json

# Store setup (same as Section A — skip if vault already exists)
npx keyhole vault create --config fixtures/sample-keyhole.yaml
```

### Run

```bash
npx keyhole migrate --config fixtures/sample-keyhole.yaml
```

### UX Checkpoints

1. **Nested key dot-path names** — detected secrets show dot-path keys like
   `Values.AzureWebJobsStorage`, `Values.MY_API_SECRET`, `ConnectionStrings.Default`
2. **Non-secret skipping** — `IsEncrypted` (boolean) and `FUNCTIONS_WORKER_RUNTIME`
   (`node` — too short) are skipped
3. **JSON structure preserved** — after cleanup, `localsettings.json` is still valid
   JSON with same structure, secret values replaced with format-aware placeholders
   (all containing `KEYHOLE_MANAGED`)
4. **Unmatched secret guidance** — all JSON secrets have no `sdk_env` match, shown
   as unmatched with generated `secret_ref` names

### Cleanup

```bash
rm -f localsettings.json .keyhole.vault
```

---

## Section B2: Migration — JSON (flat Claude settings)

Validates flat JSON detection with a `.claude/settings.json`-style file.

### Setup

```bash
# .claude/settings.json is a discoverable path in SUPPORTED_FILES
mkdir -p .claude
cp fixtures/sample-claude-settings.json .claude/settings.json

# Store setup
npx keyhole vault create --config fixtures/sample-keyhole.yaml
```

### Run

```bash
npx keyhole migrate --config fixtures/sample-keyhole.yaml
```

### UX Checkpoints

1. **`api_key` detected as secret** — suspicious key name (`key` substring) +
   long high-entropy value triggers both signals
2. **`model` and `max_tokens` skipped** — `model` is not a suspicious key name,
   `max_tokens` has a numeric value
3. **Generated `secret_ref`** — `api_key` maps to `api-key`
4. **Flat JSON cleanup** — `api_key` value replaced with a format-aware placeholder
   (containing `KEYHOLE_MANAGED`), `model` and `max_tokens` unchanged

### Cleanup

```bash
rm -rf .claude .keyhole.vault
```

---

## Section C: Migration — OpenClaw (dual flow)

Validates migration of OpenClaw configurations. OpenClaw supports two patterns:

- **Env-based (recommended):** Real keys in `.openclaw/.env`, `openclaw.json`
  references them via `${VAR}` placeholders
- **Inline (legacy):** Keys directly in `openclaw.json`

The dual-flow test validates that `${VAR}` placeholders are correctly skipped
while inline secrets are detected.

### C1: Env-based OpenClaw (dual flow)

```bash
# Set up the OpenClaw directory structure
mkdir -p .openclaw
cp fixtures/sample-openclaw-env.env .openclaw/.env
cp fixtures/sample-openclaw-env.json .openclaw/openclaw.json

# Store setup
npx keyhole vault create --config fixtures/sample-keyhole.yaml
```

```bash
npx keyhole migrate --config fixtures/sample-keyhole.yaml
```

**UX Checkpoints:**

1. **Both files discovered** — CLI reports scanning `.openclaw/.env` and
   `.openclaw/openclaw.json`
2. **Env secrets detected** — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
   `OPENROUTER_API_KEY`, `GROQ_API_KEY` from `.openclaw/.env` are detected
3. **JSON placeholders skipped** — `${OPENAI_API_KEY}`, `${ANTHROPIC_API_KEY}`,
   `${OPENROUTER_API_KEY}` in `openclaw.json` are skipped (value is a `${VAR}`
   reference, not an inline secret)
4. **JSON non-secrets skipped** — `defaultModel`, `port`, `logLevel` skipped
   (non-suspicious key names or non-secret values)
5. **Cleanup targets .env only** — cleanup prompt appears for `.openclaw/.env`
   (has secrets). No cleanup prompt for `openclaw.json` (no secrets detected)
6. **Placeholders still work** — after `.env` cleanup, `openclaw.json` still has
   `${VAR}` references pointing at the (now-managed) env vars

```bash
rm -rf .openclaw .keyhole.vault
```

### C2: Inline OpenClaw (legacy)

```bash
mkdir -p .openclaw
cp fixtures/sample-openclaw-inline.json .openclaw/openclaw.json
# No .openclaw/.env — keys are inline

npx keyhole vault create --config fixtures/sample-keyhole.yaml
```

```bash
npx keyhole migrate --config fixtures/sample-keyhole.yaml
```

**UX Checkpoints:**

1. **Only JSON discovered** — CLI reports scanning `.openclaw/openclaw.json`
   (no `.openclaw/.env` to find)
2. **Inline secrets detected** — `providers.openai.apiKey` and
   `providers.anthropic.apiKey` detected as secrets (suspicious key name `apiKey`
   + long high-entropy values)
3. **Non-secrets skipped** — `defaultModel`, `port`, `logLevel` skipped
4. **JSON cleanup** — after replace, `apiKey` values become format-aware placeholders
   (containing `KEYHOLE_MANAGED`), rest of JSON structure preserved

```bash
rm -rf .openclaw .keyhole.vault
```

---

## Section D: Masking Trap

Validates the 4-layer response masking pipeline using a local mock server
and the public `createKeyhole()` API.

### Setup

```bash
# Store setup (choose one):

# Option 1: Vault
npx keyhole vault create --config fixtures/sample-keyhole.yaml
npx keyhole vault add local-mock-token --config fixtures/sample-keyhole.yaml
# When prompted, enter: ghp_m4nualTr4pS3cret9K7xR2pL5wQ8vF0bN1c

# Option 2: Keychain
npx keyhole add local-mock-token --config fixtures/sample-keyhole.yaml
# When prompted, enter: ghp_m4nualTr4pS3cret9K7xR2pL5wQ8vF0bN1c
```

### Run

```bash
npx tsx masking-trap.ts
```

If using vault, the script prompts for your vault passphrase interactively
(no echo). If using keychain, it starts immediately.

### UX Checkpoints

1. **All checks PASS** — 8/8 checks:
   - L1: `set-cookie` scrubbed, `x-api-key` scrubbed, `content-type` preserved
   - L2: `clone_url` known-secret redacted
   - L3: `access_token` redacted (heuristic), `session_id` preserved (UUID),
     `token_type` preserved (short), `expires_in` preserved (number)
   - L4: `debug.internal_token` redacted (json_path match)
2. **Audit logger** — stderr shows sidecar startup and request/response logging
3. **Latency** — request completes within a few seconds (local server, no network)

### Cleanup

```bash
rm -f .keyhole.vault
```

---

## Section E: Error Paths

Manual scenarios to validate CLI error messaging.

### E1: Double vault creation

```bash
npx keyhole vault create
# (create successfully)
npx keyhole vault create
# Expected: error message that vault already exists
rm -f .keyhole.vault
```

### E2: Wrong passphrase on migrate

```bash
npx keyhole vault create --config fixtures/sample-keyhole.yaml
cp fixtures/sample.env .env
npx keyhole migrate --config fixtures/sample-keyhole.yaml
# When prompted for passphrase, enter the wrong one
# Expected: clear error about incorrect passphrase
rm -f .env .keyhole.vault
```

### E3: Ctrl+C during import

```bash
npx keyhole vault create --config fixtures/sample-keyhole.yaml
cp fixtures/sample.env .env
npx keyhole migrate --config fixtures/sample-keyhole.yaml
# When prompted to confirm import, press Ctrl+C
# Expected: clean exit, no partial writes, .env unchanged
rm -f .env .keyhole.vault
```

### E4: Add with no config

```bash
npx keyhole add some-service
# Expected: error about missing keyhole.yaml (or no config found)
```

### E5: List with no store

```bash
rm -f .keyhole.vault
npx keyhole list
# Expected: guidance about setting up a secret store
```

### E6: safe-repo outside a git repo

```bash
cd /tmp
npx keyhole safe-repo
# Expected: "⚠ Not a git repository. Nothing to do."
cd -
```

### E7: safe-repo idempotent (second run)

```bash
npx keyhole safe-repo
# First run: "Updated .gitignore:" with list of added entries
npx keyhole safe-repo
# Second run: "✓ .gitignore already covers all sensitive files"
# Verify: no duplicate entries in .gitignore
cat .gitignore
rm -f .gitignore
```

### E8: safe-repo detects tracked secret file

```bash
echo "SECRET=value" > .env
git add .env
npx keyhole safe-repo
# Expected: .gitignore updated AND warning:
#   ⚠ WARNING: .env is already tracked by Git.
#     Adding it to .gitignore won't remove it from history.
#     Run: git rm --cached .env
git rm --cached .env
rm -f .env .gitignore
```
