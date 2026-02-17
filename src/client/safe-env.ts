import type { ParsedConfig } from '../config/schema.js';

/**
 * Generate a format-aware placeholder that preserves the prefix of the original
 * secret value. Scans the first 12 characters for the last `_` or `-` separator
 * and uses everything up to (and including) that separator as the prefix.
 *
 * Falls back to `${serviceName}_KEYHOLE_MANAGED` when no prefix is found or
 * no original value is available.
 */
export function generatePlaceholder(serviceName: string, originalValue?: string): string {
  if (originalValue) {
    const scanRange = originalValue.substring(0, 12);
    let lastSep = -1;
    for (let i = 0; i < scanRange.length; i++) {
      if (scanRange[i] === '_' || scanRange[i] === '-') {
        lastSep = i;
      }
    }
    if (lastSep >= 0) {
      const prefix = originalValue.substring(0, lastSep + 1);
      const base = prefix + 'KEYHOLE_MANAGED';
      if (base.length >= originalValue.length) {
        return base;
      }
      return base + '0'.repeat(originalValue.length - base.length);
    }
  }
  return `${serviceName}_KEYHOLE_MANAGED`;
}

/**
 * Generate safe placeholder environment variables for legacy SDK compatibility.
 * These values look like real credentials but are dummy placeholders.
 */
export function generateSafeEnv(config: ParsedConfig): Record<string, string> {
  const env: Record<string, string> = {};

  for (const [name, service] of Object.entries(config.services)) {
    if (service.sdk_env) {
      for (const [envVar, template] of Object.entries(service.sdk_env)) {
        env[envVar] = template.replace(
          '{{placeholder}}',
          service.placeholder || generatePlaceholder(name)
        );
      }
    }
  }

  return env;
}

/**
 * Generate safe env for a specific service only.
 */
export function generateSafeEnvForService(
  config: ParsedConfig,
  serviceName: string
): Record<string, string> {
  const env: Record<string, string> = {};
  const service = config.services[serviceName];

  if (service?.sdk_env) {
    for (const [envVar, template] of Object.entries(service.sdk_env)) {
      env[envVar] = template.replace(
        '{{placeholder}}',
        service.placeholder || generatePlaceholder(serviceName)
      );
    }
  }

  return env;
}
