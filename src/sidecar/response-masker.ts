import type { ParsedConfig } from '../config/schema.js';
import { maskJsonPaths } from './json-path-redactor.js';
import type { AuditLogger } from './audit-logger.js';

const REDACTION_MARKER = '[REDACTED BY KEYHOLE]';
const MIN_SECRET_LENGTH = 8;

/** Default cap for unbounded regex quantifiers in streaming mode */
const DEFAULT_STREAMING_WINDOW_CAP = 200;

/** Maximum size of the JSON path accumulator before L4 is skipped (OOM protection) */
const MAX_ACCUMULATOR_SIZE = 10 * 1024 * 1024; // 10MB

// --- Layer 1: Header Scrubbing ---

const SCRUB_RESPONSE_HEADERS = new Set([
  'authorization',
  'www-authenticate',
  'proxy-authorization',
  'proxy-authenticate',
  'set-cookie',
  'cookie',
  'x-api-key',
  'x-amz-security-token',
  'x-amz-credential',
  'x-csrf-token',
  'x-xsrf-token'
]);

function scrubHeaders(
  headers: Record<string, string>
): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!SCRUB_RESPONSE_HEADERS.has(key.toLowerCase())) {
      clean[key] = value;
    }
  }
  return clean;
}

// --- Layer 2: Known-Secret Body Scan ---

function maskKnownSecrets(
  body: string,
  injectedSecrets: string[]
): { body: string; redacted: boolean } {
  let masked = body;
  let redacted = false;

  for (const secret of injectedSecrets) {
    if (secret.length < MIN_SECRET_LENGTH) continue;

    // Plain text match
    if (masked.includes(secret)) {
      masked = masked.replaceAll(secret, REDACTION_MARKER);
      redacted = true;
    }

    // Base64-encoded match
    const b64 = Buffer.from(secret).toString('base64');
    if (masked.includes(b64)) {
      masked = masked.replaceAll(b64, REDACTION_MARKER);
      redacted = true;
    }

    // URL-encoded match
    const urlEncoded = encodeURIComponent(secret);
    if (urlEncoded !== secret && masked.includes(urlEncoded)) {
      masked = masked.replaceAll(urlEncoded, REDACTION_MARKER);
      redacted = true;
    }
  }

  return { body: masked, redacted };
}

// --- Layer 3: Pattern-Based Redaction ---

function maskPatterns(
  body: string,
  patterns: string[]
): { body: string; redacted: boolean } {
  let masked = body;
  let redacted = false;

  for (const pattern of patterns) {
    const before = masked;
    masked = masked.replace(new RegExp(pattern, 'g'), REDACTION_MARKER);
    if (masked !== before) {
      redacted = true;
    }
  }

  return { body: masked, redacted };
}

// --- Combined Masking Pipeline ---

export class ResponseMasker {
  private config: ParsedConfig;
  private injectedSecrets: string[];
  private placeholders: Set<string>;

  constructor(config: ParsedConfig, secrets: Map<string, string>) {
    this.config = config;
    this.injectedSecrets = Array.from(secrets.values());

    // Placeholder values should NOT be redacted
    this.placeholders = new Set(
      Object.values(config.services).map(
        (s) => s.placeholder || 'KEYHOLE_MANAGED'
      )
    );
  }

  scrubHeaders(headers: Record<string, string>): Record<string, string> {
    return scrubHeaders(headers);
  }

  maskBody(
    body: string,
    serviceName: string
  ): { body: string; redacted: boolean } {
    let result = body;
    let anyRedacted = false;

    // Layer 2: Known secrets (excluding placeholders)
    const realSecrets = this.injectedSecrets.filter(
      (s) => !this.placeholders.has(s)
    );
    const l2 = maskKnownSecrets(result, realSecrets);
    result = l2.body;
    anyRedacted = anyRedacted || l2.redacted;

    // Layer 3: Service-specific patterns
    const service = this.config.services[serviceName];
    if (service?.response_masking?.patterns) {
      const l3 = maskPatterns(result, service.response_masking.patterns);
      result = l3.body;
      anyRedacted = anyRedacted || l3.redacted;
    }

    // Layer 4: JSON path redaction
    if (service?.response_masking?.json_paths) {
      const l4 = maskJsonPaths(result, service.response_masking.json_paths);
      result = l4.body;
      anyRedacted = anyRedacted || l4.redacted;
    }

    return { body: result, redacted: anyRedacted };
  }

  /** Check if response is binary. Uses Content-Type then falls back to byte sniffing. */
  isBinaryResponse(contentType: string, bodyStart?: Buffer): boolean {
    if (contentType) {
      const textTypes = [
        'text/',
        'application/json',
        'application/xml',
        'application/x-www-form-urlencoded',
        'application/javascript'
      ];
      if (textTypes.some((t) => contentType.toLowerCase().includes(t))) {
        return false;
      }
      if (contentType.toLowerCase().includes('application/octet-stream'))
        return true;
      if (contentType.toLowerCase().includes('image/')) return true;
      if (contentType.toLowerCase().includes('audio/')) return true;
      if (contentType.toLowerCase().includes('video/')) return true;
    }

    if (bodyStart) {
      const sample = bodyStart.subarray(0, 512);
      for (let i = 0; i < sample.length; i++) {
        const byte = sample[i];
        if (byte === 0) return true;
        if (byte < 8 || (byte > 13 && byte < 32)) return true;
      }
    }

    return false;
  }

  getInjectedSecrets(): string[] {
    return this.injectedSecrets;
  }
}

// --- Streaming Support ---

export class StreamingMasker {
  private windowSize: number;
  private buffer: string = '';
  private masker: ResponseMasker;
  private serviceName: string;
  private hasJsonPaths: boolean;
  private jsonPathAccumulator: string = '';
  private jsonPathAccumulatorOverflow = false;
  private logger?: AuditLogger;

  constructor(
    masker: ResponseMasker,
    secrets: string[],
    serviceName: string,
    config: ParsedConfig,
    logger?: AuditLogger
  ) {
    this.masker = masker;
    this.serviceName = serviceName;
    this.logger = logger;

    const service = config.services[serviceName];
    this.hasJsonPaths = !!(service?.response_masking?.json_paths?.length);

    const windowCap =
      service?.response_masking?.streaming_window_cap ??
      DEFAULT_STREAMING_WINDOW_CAP;

    // Window = max of (longest secret across encodings, longest regex match estimate)
    this.windowSize = 0;

    for (const secret of secrets) {
      this.windowSize = Math.max(
        this.windowSize,
        secret.length,
        Buffer.from(secret).toString('base64').length,
        encodeURIComponent(secret).length
      );
    }

    if (service?.response_masking?.patterns) {
      for (const pattern of service.response_masking.patterns) {
        this.windowSize = Math.max(
          this.windowSize,
          estimateMaxMatchLength(pattern, windowCap)
        );
      }
    }

    this.windowSize += 10; // Safety margin
  }

  processChunk(chunk: string): { output: string; redacted: boolean } {
    const combined = this.buffer + chunk;

    // Accumulate for deferred JSON path redaction (with OOM protection)
    if (this.hasJsonPaths && !this.jsonPathAccumulatorOverflow) {
      if (
        this.jsonPathAccumulator.length + chunk.length >
        MAX_ACCUMULATOR_SIZE
      ) {
        this.jsonPathAccumulatorOverflow = true;
        this.jsonPathAccumulator = ''; // Free memory immediately
        this.logger?.warn(
          'response.accumulator_overflow',
          {
            service: this.serviceName,
            error:
              `Response exceeded ${MAX_ACCUMULATOR_SIZE} bytes. ` +
              `Layer 4 (json_paths) masking will be skipped. ` +
              `Layers 2 and 3 still apply.`
          }
        );
      } else {
        this.jsonPathAccumulator += chunk;
      }
    }

    if (combined.length <= this.windowSize) {
      this.buffer = combined;
      return { output: '', redacted: false };
    }

    const safeLength = combined.length - this.windowSize;
    const safeRegion = combined.substring(0, safeLength);
    this.buffer = combined.substring(safeLength);

    // Apply L2 and L3 only during streaming; L4 is deferred to flush
    const { body, redacted } = this.masker.maskBody(safeRegion, this.serviceName);
    return { output: body, redacted };
  }

  flush(): { output: string; redacted: boolean } {
    let result = this.buffer;
    this.buffer = '';

    // Apply L2 and L3
    let { body: masked, redacted } = this.masker.maskBody(
      result,
      this.serviceName
    );

    // Apply deferred L4 (JSON path) on full accumulated response
    if (
      this.hasJsonPaths &&
      !this.jsonPathAccumulatorOverflow &&
      this.jsonPathAccumulator
    ) {
      const service = this.masker['config'].services[this.serviceName];
      if (service?.response_masking?.json_paths) {
        const l4 = maskJsonPaths(
          this.jsonPathAccumulator,
          service.response_masking.json_paths
        );
        if (l4.redacted) {
          masked = l4.body;
          redacted = true;
        }
      }
      this.jsonPathAccumulator = '';
    }

    return { output: masked, redacted };
  }
}

// --- Helpers ---

function estimateMaxMatchLength(pattern: string, cap: number): number {
  let p = pattern.replace(/^\^|\$$/g, '');
  let length = 0;
  let i = 0;

  while (i < p.length) {
    if (p[i] === '[') {
      const end = p.indexOf(']', i);
      if (end === -1) {
        length += 1;
        i++;
        continue;
      }
      i = end + 1;
      const q = parseQuantifier(p, i, cap);
      length += q.max;
      i = q.nextIndex;
    } else if (p[i] === '\\') {
      i += 2;
      const q = parseQuantifier(p, i, cap);
      length += q.max;
      i = q.nextIndex;
    } else {
      i++;
      const q = parseQuantifier(p, i, cap);
      length += q.max;
      i = q.nextIndex;
    }
  }
  return length;
}

function parseQuantifier(
  p: string,
  i: number,
  cap: number
): { max: number; nextIndex: number } {
  if (i >= p.length) return { max: 1, nextIndex: i };
  if (p[i] === '{') {
    const end = p.indexOf('}', i);
    if (end !== -1) {
      const inner = p.substring(i + 1, end);
      const parts = inner.split(',');
      const max =
        parts.length > 1
          ? parseInt(parts[1] || String(cap))
          : parseInt(parts[0]);
      return { max: isNaN(max) ? cap : max, nextIndex: end + 1 };
    }
  }
  if (p[i] === '+' || p[i] === '*') return { max: cap, nextIndex: i + 1 };
  if (p[i] === '?') return { max: 1, nextIndex: i + 1 };
  return { max: 1, nextIndex: i };
}
