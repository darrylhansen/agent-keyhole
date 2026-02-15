import type { ParsedConfig, HeuristicConfig } from '../config/schema.js';
import { SecretRegistry } from './secret-registry.js';
import { shouldRedactHeuristic } from './heuristic-detector.js';
import { redactJsonPaths } from './json-path-redactor.js';
import type { AuditLogger } from './audit-logger.js';

const REDACTION_MARKER = '[REDACTED BY KEYHOLE]';

/** Default cap for unbounded regex quantifiers in streaming mode */
const DEFAULT_STREAMING_WINDOW_CAP = 200;

/** Maximum size of the accumulator before deferred masking is skipped (OOM protection) */
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

// --- Combined Masking Pipeline ---

export interface MaskBodyResult {
  body: string;
  redacted: boolean;
  layers: string[];
  heuristicKeys: string[];
}

export class ResponseMasker {
  private config: ParsedConfig;
  private registry: SecretRegistry;

  constructor(config: ParsedConfig, registry: SecretRegistry) {
    this.config = config;
    this.registry = registry;
  }

  scrubHeaders(headers: Record<string, string>): Record<string, string> {
    return scrubHeaders(headers);
  }

  maskBody(body: string, serviceName: string): MaskBodyResult {
    let anyRedacted = false;
    const layers: string[] = [];
    const heuristicKeys: string[] = [];
    const service = this.config.services[serviceName];
    const heuristicConfig = service?.response_masking?.heuristic;
    const heuristicEnabled = heuristicConfig?.enabled !== false;

    // Attempt JSON parse
    let parsed: any;
    let isJson = false;
    try {
      parsed = JSON.parse(body);
      if (typeof parsed === 'object' && parsed !== null) {
        isJson = true;
      }
    } catch {
      // Not JSON
    }

    let result: string;

    if (isJson) {
      // JSON path: deep walk for L2 (structural) + L3 (heuristic)
      const walkResult = this.walkAndMask(
        parsed, heuristicEnabled, heuristicConfig
      );
      if (walkResult.redacted) {
        anyRedacted = true;
        if (walkResult.l2Hit) layers.push('known_secret');
        if (walkResult.l3Hit) layers.push('heuristic');
        heuristicKeys.push(...walkResult.heuristicKeys);
      }

      // L4: user json_paths (operates on already-parsed object)
      if (service?.response_masking?.json_paths) {
        const l4 = redactJsonPaths(parsed, service.response_masking.json_paths);
        if (l4) {
          anyRedacted = true;
          if (!layers.includes('json_path')) layers.push('json_path');
        }
      }

      result = JSON.stringify(parsed);

      // L4: user patterns (raw text on serialized result)
      if (service?.response_masking?.patterns) {
        const l4p = this.applyPatterns(result, service.response_masking.patterns);
        result = l4p.body;
        if (l4p.redacted) {
          anyRedacted = true;
          if (!layers.includes('pattern')) layers.push('pattern');
        }
      }
    } else {
      // Non-JSON: L2 raw text substring scan
      const l2 = this.registry.replaceAllSubstrings(body, REDACTION_MARKER);
      result = l2.result;
      if (l2.replaced) {
        anyRedacted = true;
        layers.push('known_secret');
      }

      // L4: user patterns (raw text)
      if (service?.response_masking?.patterns) {
        const l4p = this.applyPatterns(result, service.response_masking.patterns);
        result = l4p.body;
        if (l4p.redacted) {
          anyRedacted = true;
          if (!layers.includes('pattern')) layers.push('pattern');
        }
      }
      // L3 heuristic is JSON-only. Non-JSON responses rely on L2.
      // L4 json_paths require JSON — skipped for non-JSON.
    }

    return { body: result, redacted: anyRedacted, layers, heuristicKeys };
  }

  private walkAndMask(
    obj: any,
    heuristicEnabled: boolean,
    heuristicConfig?: HeuristicConfig
  ): { redacted: boolean; l2Hit: boolean; l3Hit: boolean; heuristicKeys: string[] } {
    let l2Hit = false;
    let l3Hit = false;
    const heuristicKeys: string[] = [];

    const walk = (node: any, parentKey?: string): void => {
      if (node === null || node === undefined) return;
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i++) {
          if (typeof node[i] === 'string') {
            const r = this.maskStringValue(
              node[i], undefined, heuristicEnabled, heuristicConfig
            );
            if (r.replaced) {
              node[i] = r.value;
              if (r.l2) l2Hit = true;
              if (r.l3) l3Hit = true;
              if (r.l3Key) heuristicKeys.push(r.l3Key);
            }
          } else if (typeof node[i] === 'object') {
            walk(node[i]);
          }
        }
      } else if (typeof node === 'object') {
        for (const key of Object.keys(node)) {
          if (typeof node[key] === 'string') {
            const r = this.maskStringValue(
              node[key], key, heuristicEnabled, heuristicConfig
            );
            if (r.replaced) {
              node[key] = r.value;
              if (r.l2) l2Hit = true;
              if (r.l3) l3Hit = true;
              if (r.l3Key) heuristicKeys.push(r.l3Key);
            }
          } else if (typeof node[key] === 'object' && node[key] !== null) {
            walk(node[key], key);
          }
        }
      }
    };

    walk(obj);
    return { redacted: l2Hit || l3Hit, l2Hit, l3Hit, heuristicKeys };
  }

  private maskStringValue(
    value: string,
    key: string | undefined,
    heuristicEnabled: boolean,
    heuristicConfig?: HeuristicConfig
  ): { value: string; replaced: boolean; l2: boolean; l3: boolean; l3Key?: string } {
    // L2: Exact match
    if (this.registry.hasExact(value)) {
      return { value: REDACTION_MARKER, replaced: true, l2: true, l3: false };
    }

    // L2: Substring match
    const sub = this.registry.replaceAllSubstrings(value, REDACTION_MARKER);
    if (sub.replaced) {
      return { value: sub.result, replaced: true, l2: true, l3: false };
    }

    // L3: Heuristic (only if we have a key name and L2 didn't touch the value)
    if (heuristicEnabled && key !== undefined) {
      if (shouldRedactHeuristic(key, value, {
        minLength: heuristicConfig?.min_length,
        minEntropy: heuristicConfig?.min_entropy,
        additionalKeyNames: heuristicConfig?.additional_key_names,
      })) {
        return {
          value: REDACTION_MARKER,
          replaced: true,
          l2: false,
          l3: true,
          l3Key: key
        };
      }
    }

    return { value, replaced: false, l2: false, l3: false };
  }

  private applyPatterns(
    body: string,
    patterns: string[]
  ): { body: string; redacted: boolean } {
    let masked = body;
    let redacted = false;
    for (const pattern of patterns) {
      const before = masked;
      masked = masked.replace(new RegExp(pattern, 'g'), REDACTION_MARKER);
      if (masked !== before) redacted = true;
    }
    return { body: masked, redacted };
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

  getRegistry(): SecretRegistry {
    return this.registry;
  }
}

// --- Streaming Support ---

export class StreamingMasker {
  private windowSize: number;
  private buffer: string = '';
  private masker: ResponseMasker;
  private serviceName: string;
  private hasJsonPaths: boolean;
  private hasHeuristic: boolean;
  private accumulator: string = '';
  private accumulatorOverflow = false;
  private logger?: AuditLogger;

  constructor(
    masker: ResponseMasker,
    serviceName: string,
    config: ParsedConfig,
    logger?: AuditLogger
  ) {
    this.masker = masker;
    this.serviceName = serviceName;
    this.logger = logger;

    const service = config.services[serviceName];
    this.hasJsonPaths = !!(service?.response_masking?.json_paths?.length);
    this.hasHeuristic = service?.response_masking?.heuristic?.enabled !== false;

    const windowCap =
      service?.response_masking?.streaming_window_cap ??
      DEFAULT_STREAMING_WINDOW_CAP;

    // Window = max variant length across all registry entries
    this.windowSize = 0;
    const registry = masker.getRegistry();
    for (const variant of registry.getAllVariants()) {
      this.windowSize = Math.max(this.windowSize, variant.length);
    }

    // Plus regex pattern estimates
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

    // Accumulate for deferred L3 heuristic + L4 json_paths (with OOM protection)
    const needsAccumulation = this.hasJsonPaths || this.hasHeuristic;
    if (needsAccumulation && !this.accumulatorOverflow) {
      if (
        this.accumulator.length + chunk.length >
        MAX_ACCUMULATOR_SIZE
      ) {
        this.accumulatorOverflow = true;
        this.accumulator = ''; // Free memory immediately
        this.logger?.warn(
          'response.accumulator_overflow',
          {
            service: this.serviceName,
            error:
              `Response exceeded ${MAX_ACCUMULATOR_SIZE} bytes. ` +
              `L3 (heuristic) and L4 (json_paths) masking will be skipped. ` +
              `L2 (known secrets) and L4 (patterns) still apply.`
          }
        );
      } else {
        this.accumulator += chunk;
      }
    }

    if (combined.length <= this.windowSize) {
      this.buffer = combined;
      return { output: '', redacted: false };
    }

    const safeLength = combined.length - this.windowSize;
    const safeRegion = combined.substring(0, safeLength);
    this.buffer = combined.substring(safeLength);

    // During streaming: chunks are partial strings, not valid JSON.
    // maskBody() will fall through to the non-JSON branch, applying
    // L2 raw substring scan + L4 patterns. L3 heuristic is deferred to flush.
    const { body, redacted } = this.masker.maskBody(safeRegion, this.serviceName);
    return { output: body, redacted };
  }

  flush(): { output: string; redacted: boolean } {
    const remaining = this.buffer;
    this.buffer = '';

    // If we accumulated the full response, run the full pipeline on it
    // (L2 structural JSON scan + L3 heuristic + L4 json_paths + L4 patterns)
    if (
      (this.hasJsonPaths || this.hasHeuristic) &&
      !this.accumulatorOverflow &&
      this.accumulator
    ) {
      const full = this.masker.maskBody(this.accumulator, this.serviceName);
      this.accumulator = '';
      return { output: full.body, redacted: full.redacted };
    }

    // Fallback: run pipeline on just the remaining buffer
    const { body: masked, redacted } = this.masker.maskBody(
      remaining,
      this.serviceName
    );
    this.accumulator = '';
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
