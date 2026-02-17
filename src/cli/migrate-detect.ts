import { isSuspiciousKeyName } from '../sidecar/heuristic-detector.js';
import type { ParsedConfig } from '../config/schema.js';
import type { ExtractedEntry } from './migrate-parsers.js';

/**
 * Additional env var suffix patterns beyond the heuristic detector's list.
 */
const SECRET_SUFFIXES = [
  '_TOKEN', '_SECRET', '_KEY', '_PASSWORD', '_API_KEY',
  '_CREDENTIALS', '_AUTH', '_DSN', '_CONNECTION_STRING',
];

export interface SecretCandidate {
  entry: ExtractedEntry;
  secretRef: string;
  matchedService: string | null;
  isSecret: boolean;
  skipReason?: string;
}

/**
 * Check if a key name looks like it holds a secret.
 * Uses the heuristic detector's suspicious key list + env var suffix patterns.
 */
export function isSecretKeyName(key: string): boolean {
  // Use the leaf key name (last segment for JSON paths)
  const leafKey = key.includes('.') ? key.split('.').pop()! : key;

  // Check against heuristic detector's suspicious key list
  if (isSuspiciousKeyName(leafKey)) return true;

  // Check env var suffix patterns
  const upper = leafKey.toUpperCase();
  for (const suffix of SECRET_SUFFIXES) {
    if (upper.endsWith(suffix)) return true;
  }

  return false;
}

/**
 * Check if a value looks like a credential (not a non-secret config value).
 */
export function isSecretValue(value: string): boolean {
  // Too short to be a secret
  if (value.length <= 8) return false;

  // Skip obvious non-secrets
  const lower = value.toLowerCase();
  if (lower === 'true' || lower === 'false') return false;
  if (/^\d+(\.\d+)?$/.test(value)) return false;

  // Skip placeholders
  if (value.includes('KEYHOLE_MANAGED') || value === '') return false;

  // Skip env var references (e.g. ${OPENAI_API_KEY} in openclaw.json)
  if (/^\$\{.+\}$/.test(value)) return false;

  // URLs are not secrets unless they contain embedded credentials
  if (/^https?:\/\//i.test(value)) {
    // Check for embedded credentials: scheme://user:pass@host
    try {
      const url = new URL(value);
      return url.password !== '';
    } catch {
      return false;
    }
  }

  return true;
}

/**
 * Convert an env var name to a secret_ref slug.
 * e.g. GITHUB_TOKEN → github-token, Values.DATABASE_URL → values-database-url
 */
export function toSecretRef(key: string): string {
  return key
    .toLowerCase()
    .replace(/[._]/g, '-')
    .replace(/--+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Build a reverse mapping: env var name → { serviceName, secretRef }
 * by reading sdk_env from each service in the config.
 */
function buildEnvToServiceMap(
  config: ParsedConfig
): Map<string, { service: string; secretRef: string }> {
  const map = new Map<string, { service: string; secretRef: string }>();

  for (const [name, service] of Object.entries(config.services)) {
    if (service.sdk_env) {
      for (const envVar of Object.keys(service.sdk_env)) {
        map.set(envVar, {
          service: name,
          secretRef: service.auth.secret_ref,
        });
      }
    }

    // Also try matching by common convention: service name in the env var
    // e.g. service "github" matches GITHUB_TOKEN
    const secretRef = service.auth.secret_ref;
    map.set(`__service_ref:${secretRef}`, { service: name, secretRef });
  }

  return map;
}

/**
 * Filter and classify extracted entries as secrets or non-secrets.
 * Optionally match to configured services.
 */
export function detectSecrets(
  entries: ExtractedEntry[],
  config?: ParsedConfig
): SecretCandidate[] {
  const envMap = config ? buildEnvToServiceMap(config) : new Map();

  return entries.map((entry) => {
    const leafKey = entry.key.includes('.')
      ? entry.key.split('.').pop()!
      : entry.key;

    const keyIsSecret = isSecretKeyName(entry.key);
    const valueIsSecret = isSecretValue(entry.value);
    const isSecret = keyIsSecret && valueIsSecret;

    // Determine skip reason for non-secrets
    let skipReason: string | undefined;
    if (!isSecret) {
      if (!keyIsSecret) skipReason = 'not a secret';
      else if (!valueIsSecret) skipReason = 'value too short or non-secret';
    }

    // Try to match to a configured service
    let matchedService: string | null = null;
    let secretRef = toSecretRef(leafKey);

    if (config) {
      // Direct sdk_env match
      const directMatch = envMap.get(leafKey);
      if (directMatch) {
        matchedService = directMatch.service;
        secretRef = directMatch.secretRef;
      } else {
        // Try matching by generated secret_ref against configured secret_refs
        const generatedRef = toSecretRef(leafKey);
        const refMatch = envMap.get(`__service_ref:${generatedRef}`);
        if (refMatch) {
          matchedService = refMatch.service;
          secretRef = refMatch.secretRef;
        }
      }
    }

    return {
      entry,
      secretRef,
      matchedService,
      isSecret,
      skipReason,
    };
  });
}

/**
 * Find duplicate keys across files. Returns keys that appear more than once.
 */
export function findDuplicates(
  candidates: SecretCandidate[]
): Map<string, SecretCandidate[]> {
  const byRef = new Map<string, SecretCandidate[]>();

  for (const c of candidates) {
    if (!c.isSecret) continue;
    const group = byRef.get(c.secretRef) || [];
    group.push(c);
    byRef.set(c.secretRef, group);
  }

  // Only return groups with duplicates
  const dupes = new Map<string, SecretCandidate[]>();
  for (const [ref, group] of byRef) {
    if (group.length > 1) {
      dupes.set(ref, group);
    }
  }

  return dupes;
}
