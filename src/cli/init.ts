import fs from 'fs';
import path from 'path';

const TEMPLATE = `# keyhole.yaml – Agent-Keyhole configuration
# Documentation: https://github.com/agent-keyhole/agent-keyhole

services:
  # Example: GitHub API
  # github:
  #   domains:
  #     - api.github.com
  #   auth:
  #     type: bearer
  #     secret_ref: github-token
  #   placeholder: "KEYHOLE_MANAGED"
  #   sdk_env:
  #     GITHUB_TOKEN: "{{placeholder}}"
  #   headers:
  #     Accept: application/vnd.github+json
  #     X-GitHub-Api-Version: "2022-11-28"
  #   response_masking:
  #     patterns:
  #       - "ghp_[A-Za-z0-9_]{36}"

  # Example: OpenAI API
  # openai:
  #   domains:
  #     - api.openai.com
  #   auth:
  #     type: bearer
  #     secret_ref: openai-api-key
  #   placeholder: "sk-keyhole-000000000000000000000000000000000000000000000000"
  #   sdk_env:
  #     OPENAI_API_KEY: "{{placeholder}}"
  #   response_masking:
  #     patterns:
  #       - "sk-[A-Za-z0-9]{20,}"

# Optional: Multi-agent access control
# agents:
#   content-bot:
#     services: [github, openai]

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
    console.error(`Error: ${configPath} already exists.`);
    console.error('Delete it first or edit it directly.');
    process.exit(1);
  }

  fs.writeFileSync(configPath, TEMPLATE, 'utf-8');
  console.error(`✔ Created ${configPath} with example configuration`);
  console.error('  Edit the file to add your services, then run:');
  console.error('  npx keyhole add <service-name>');
}

function getConfigPath(args: string[]): string {
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    return path.resolve(args[configIdx + 1]);
  }
  return path.resolve('keyhole.yaml');
}
