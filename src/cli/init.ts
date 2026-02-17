import fs from 'fs';
import os from 'os';
import { promptConfirm, getConfigPath } from './shared.js';
import { safeRepo } from './safe-repo.js';

const TEMPLATE = `# keyhole.yaml – Agent-Keyhole configuration
# Documentation: https://github.com/darrylhansen/agent-keyhole

services:
  # ─── How SDKs get credentials ───
  #
  # If you have a .env file (e.g. after running "npx keyhole migrate"):
  #   SDKs read placeholder values from .env automatically.
  #   No additional configuration needed — Keyhole intercepts by domain.
  #
  # If you do NOT have a .env file (programmatic setup):
  #   Add sdk_env to map env var names to placeholders:
  #
  #   sdk_env:
  #     GITHUB_TOKEN: "KEYHOLE_MANAGED"
  #
  #   Then in your code: Object.assign(process.env, kh.getSafeEnv())
  #
  # If an SDK validates key format (e.g. OpenAI checks for "sk-" prefix):
  #   Set a format-aware placeholder:
  #
  #   placeholder: "sk-keyhole-0000000000000000000000000000000000000000"

  # github:
  #   domains:
  #     - api.github.com
  #   auth:
  #     type: bearer
  #     secret_ref: github-token
  #   headers:
  #     Accept: application/vnd.github+json
  #     X-GitHub-Api-Version: "2022-11-28"

  # openai:
  #   domains:
  #     - api.openai.com
  #   auth:
  #     type: bearer
  #     secret_ref: openai-api-key
  #   # OpenAI SDK validates key format — placeholder must start with "sk-"
  #   placeholder: "sk-keyhole-000000000000000000000000000000000000000000000000"
  #   # Only needed if NOT using a .env file:
  #   sdk_env:
  #     OPENAI_API_KEY: "{{placeholder}}"

  # anthropic:
  #   domains:
  #     - api.anthropic.com
  #   auth:
  #     type: custom_header
  #     header_name: x-api-key
  #     secret_ref: anthropic-api-key
  #   placeholder: "sk-ant-keyhole-000000000000000000000000000000000000"
  #   # Only needed if NOT using a .env file:
  #   sdk_env:
  #     ANTHROPIC_API_KEY: "{{placeholder}}"

# Optional: Multi-agent access control
# agents:
#   content-bot:
#     services: [github, openai]
#   deploy-bot:
#     services: [github]

# Optional: Logging
# logging:
#   output: stderr
#   level: info

# Optional: VPS alerting
# alerting:
#   webhook_url: https://discord.com/api/webhooks/xxx/yyy
#   message_prefix: "my-project"
`;

export async function initCommand(args: string[]): Promise<void> {
  const configPath = getConfigPath(args);

  if (fs.existsSync(configPath)) {
    const overwrite = await promptConfirm(
      `${configPath} already exists. Overwrite? [y/N] `
    );
    if (!overwrite) {
      console.error('Aborted.');
      return;
    }
  }

  fs.writeFileSync(configPath, TEMPLATE, 'utf-8');
  console.error(`Created ${configPath}`);
  console.error('  Next: uncomment a service example and run "npx keyhole add <service-name>"');
  console.error('  Or run "npx keyhole migrate" to import secrets from .env files.');

  // Detect secret store environment and print guidance
  try {
    const { testKeychainAccess } = await import('../store/keychain.js');
    await testKeychainAccess();
    const platform = os.platform();
    const name = platform === 'darwin' ? 'macOS Keychain' : 'libsecret';
    console.error(`  OS keychain detected (${name}). Secrets will be stored securely.`);
  } catch {
    console.error('  No OS keychain detected. You\'ll need an encrypted vault:');
    console.error('  npx keyhole vault create');
  }

  safeRepo({ silent: true });
}
