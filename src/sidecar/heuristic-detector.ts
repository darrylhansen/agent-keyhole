export const HEURISTIC_MIN_LENGTH = 16;
export const HEURISTIC_MIN_ENTROPY = 3.5;

export const SUSPICIOUS_KEY_NAMES: string[] = [
  'token', 'secret', 'key', 'password', 'passwd', 'credential', 'auth',
  'api_key', 'apikey', 'access_token', 'refresh_token', 'id_token',
  'client_secret', 'private_key', 'signing_key', 'encryption_key',
  'bearer', 'session_id', 'sid', 'salt', 'hash', 'cert', 'certificate',
  'webhook_secret', 'signing_secret', 'shared_secret', 'passphrase',
  'conn_str', 'connection_string', 'dsn'
];

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isSuspiciousKeyName(
  key: string,
  additionalNames?: string[]
): boolean {
  const lowered = key.toLowerCase();
  const names = additionalNames
    ? SUSPICIOUS_KEY_NAMES.concat(additionalNames)
    : SUSPICIOUS_KEY_NAMES;

  for (const name of names) {
    if (lowered.includes(name)) return true;
  }
  return false;
}

export function isExcludedPattern(value: string): boolean {
  if (UUID_RE.test(value)) return true;
  if (OBJECT_ID_RE.test(value)) return true;
  if (value.startsWith('http://') || value.startsWith('https://')) return true;
  if (ISO_TIMESTAMP_RE.test(value)) return true;
  if (EMAIL_RE.test(value)) return true;
  return false;
}

export function isHighEntropyValue(
  value: string,
  minLength?: number,
  minEntropy?: number
): boolean {
  if (value.length <= (minLength ?? HEURISTIC_MIN_LENGTH)) return false;
  if (isExcludedPattern(value)) return false;
  return shannonEntropy(value) > (minEntropy ?? HEURISTIC_MIN_ENTROPY);
}

export function shouldRedactHeuristic(
  key: string,
  value: string,
  options?: {
    minLength?: number;
    minEntropy?: number;
    additionalKeyNames?: string[];
  }
): boolean {
  return (
    isSuspiciousKeyName(key, options?.additionalKeyNames) &&
    isHighEntropyValue(value, options?.minLength, options?.minEntropy)
  );
}
