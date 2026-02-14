const REDACTION_MARKER = '[REDACTED BY KEYHOLE]';

/**
 * Redact values at specified JSON paths in a parsed JSON object.
 * Mutates the object in-place and returns whether any redaction occurred.
 */
export function redactJsonPaths(obj: any, paths: string[]): boolean {
  let redacted = false;

  for (const path of paths) {
    const segments = parseJsonPath(path);
    if (segments.length === 0) continue;
    redacted = walkAndRedact(obj, segments, 0) || redacted;
  }

  return redacted;
}

/**
 * Parse a JSONPath string into path segments.
 * Supports: $.foo.bar, $.foo[*].bar, $.foo[0].bar
 */
export function parseJsonPath(path: string): Array<string | '*'> {
  // Strip leading "$." or "$"
  let p = path.startsWith('$.')
    ? path.slice(2)
    : path.startsWith('$')
      ? path.slice(1)
      : path;

  const segments: Array<string | '*'> = [];
  const parts = p.split(/\.|\[|\]/).filter((s) => s !== '');

  for (const part of parts) {
    if (part === '*') {
      segments.push('*');
    } else {
      segments.push(part);
    }
  }

  return segments;
}

/**
 * Recursively walk an object and redact values at the target path.
 */
function walkAndRedact(
  obj: any,
  segments: Array<string | '*'>,
  index: number
): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (index >= segments.length) return false;

  const segment = segments[index];
  const isLast = index === segments.length - 1;

  if (segment === '*') {
    // Wildcard: iterate all elements (array) or all values (object)
    let redacted = false;
    const keys = Object.keys(obj);
    for (const key of keys) {
      if (isLast) {
        if (obj[key] !== undefined && typeof obj[key] === 'string') {
          obj[key] = REDACTION_MARKER;
          redacted = true;
        }
      } else {
        redacted = walkAndRedact(obj[key], segments, index + 1) || redacted;
      }
    }
    return redacted;
  }

  if (isLast) {
    if (segment in obj && typeof obj[segment] === 'string') {
      obj[segment] = REDACTION_MARKER;
      return true;
    }
    return false;
  }

  return walkAndRedact(obj[segment], segments, index + 1);
}

/**
 * Apply JSON path redaction to a response body string.
 * Only applies if body is valid JSON. Non-JSON bodies are returned unmodified.
 */
export function maskJsonPaths(
  body: string,
  jsonPaths: string[]
): { body: string; redacted: boolean } {
  let parsed: any;
  try {
    parsed = JSON.parse(body);
  } catch {
    // Not valid JSON — skip JSON path masking
    return { body, redacted: false };
  }

  const redacted = redactJsonPaths(parsed, jsonPaths);

  if (redacted) {
    return { body: JSON.stringify(parsed), redacted: true };
  }

  return { body, redacted: false };
}
