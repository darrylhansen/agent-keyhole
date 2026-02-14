import os from 'os';
import type { ParsedConfig } from '../config/schema.js';

export async function sendBootAlert(config: ParsedConfig): Promise<void> {
  if (!config.alerting?.webhook_url) return;

  const prefix = config.alerting.message_prefix || 'Agent-Keyhole';
  const hostname = os.hostname();
  const timestamp = new Date().toISOString();

  const payload = {
    content:
      `⚠️ **${prefix}** is locked and waiting for vault passphrase.\n` +
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
  } catch (err: any) {
    console.error(`[keyhole] Failed to send boot alert: ${err.message}`);
  }
}
