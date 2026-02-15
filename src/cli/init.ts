import fs from 'fs';
import os from 'os';
import { promptConfirm, getConfigPath } from './shared.js';

const TEMPLATE = `# keyhole.yaml – Agent-Keyhole configuration
# Documentation: https://github.com/darrylhansen/agent-keyhole

services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    headers:
      Accept: application/vnd.github+json
      X-GitHub-Api-Version: "2022-11-28"
    # Response masking is automatic — no configuration needed.
    # Keyhole detects and redacts known secrets and credential-like values.

    # Optional: Only needed with autoPatch mode so SDKs see a fake key in process.env
    # sdk_env:
    #   GITHUB_TOKEN: "{{placeholder}}"
    # Optional: Fake key format for SDKs that validate key format (default: KEYHOLE_MANAGED)
    # placeholder: "KEYHOLE_MANAGED"

    # Optional: Manual response masking overrides (rarely needed)
    # response_masking:
    #   patterns:
    #     - "ghp_[A-Za-z0-9_]{36}"
    #   json_paths:
    #     - "$.token"

  # openai:
  #   domains:
  #     - api.openai.com
  #   auth:
  #     type: bearer
  #     secret_ref: openai-api-key
  #   # OpenAI SDK validates key format, so placeholder must look like a real key
  #   placeholder: "sk-keyhole-000000000000000000000000000000000000000000000000"
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
  console.error(`Created ${configPath} with example configuration`);
  console.error('  Edit the file to add your services, then run:');
  console.error('  npx keyhole add <service-name>');

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
}
