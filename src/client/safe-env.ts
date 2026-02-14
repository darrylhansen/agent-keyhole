import type { ParsedConfig } from '../config/schema.js';

/**
 * Generate safe placeholder environment variables for legacy SDK compatibility.
 * These values look like real credentials but are dummy placeholders.
 */
export function generateSafeEnv(config: ParsedConfig): Record<string, string> {
  const env: Record<string, string> = {};

  for (const [_name, service] of Object.entries(config.services)) {
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
        service.placeholder || 'KEYHOLE_MANAGED'
      );
    }
  }

  return env;
}
