/**
 * Known text Content-Type prefixes. If a Content-Type starts with one of these,
 * the body is safe to encode as UTF-8 for IPC transport.
 */
const TEXT_CONTENT_TYPES = [
  'text/',
  'application/json',
  'application/xml',
  'application/x-www-form-urlencoded',
  'application/javascript',
  'application/graphql'
];

/**
 * Determine whether a request body should be treated as binary for IPC transport.
 *
 * Returns true if the body must be Base64-encoded to avoid corruption.
 * Returns false if the body is safe to encode as UTF-8 string.
 */
export function isBodyBinary(
  contentType: string | undefined,
  body: Buffer | string | undefined
): boolean {
  // Strings are always text
  if (typeof body === 'string') return false;

  // No body — doesn't matter, but default to text
  if (!body) return false;

  // Check Content-Type first
  if (contentType) {
    const lower = contentType.toLowerCase();
    if (
      TEXT_CONTENT_TYPES.some((t) => lower.startsWith(t) || lower.includes(t))
    ) {
      return false;
    }
    // Explicit binary types
    if (
      lower.includes('application/octet-stream') ||
      lower.includes('image/') ||
      lower.includes('audio/') ||
      lower.includes('video/') ||
      lower.includes('multipart/')
    ) {
      return true;
    }
  }

  // Fall back to byte sniffing for Buffers with unknown Content-Type
  if (Buffer.isBuffer(body)) {
    const sample = body.subarray(0, 512);
    for (let i = 0; i < sample.length; i++) {
      const byte = sample[i];
      if (byte === 0) return true;
      if (byte < 8 || (byte > 13 && byte < 32)) return true;
    }
  }

  return false;
}
