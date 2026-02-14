import fs from 'fs';
import type { LoggingConfig, ServiceConfig } from '../config/schema.js';

export interface AuditLogEntry {
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  event: string;
  service?: string;
  method?: string;
  path?: string;
  status?: number;
  duration_ms?: number;
  redacted?: boolean;
  redaction_count?: number;
  redaction_layers?: string[];
  agent?: string;
  error?: string;
}

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

export class AuditLogger {
  private level: number;
  private output: NodeJS.WritableStream;
  private verbose: boolean;

  constructor(config?: LoggingConfig) {
    this.level = LOG_LEVELS[config?.level || 'info'];
    this.verbose = config?.verbose || false;

    if (!config?.output || config.output === 'stderr') {
      this.output = process.stderr;
    } else if (config.output === 'stdout') {
      this.output = process.stdout;
    } else {
      this.output = fs.createWriteStream(config.output, { flags: 'a' });
    }
  }

  log(entry: Omit<AuditLogEntry, 'timestamp' | 'level' | 'event'> & { event?: string }): void {
    this.writeEntry({
      ...entry,
      level: 'info',
      event: entry.event || 'request.proxied'
    });
  }

  debug(message: string, extra?: Partial<AuditLogEntry>): void {
    this.writeEntry({ ...extra, level: 'debug', event: message });
  }

  info(message: string, extra?: Partial<AuditLogEntry>): void {
    this.writeEntry({ ...extra, level: 'info', event: message });
  }

  warn(message: string, extra?: Partial<AuditLogEntry>): void {
    this.writeEntry({ ...extra, level: 'warn', event: message });
  }

  error(message: string, extra?: Partial<AuditLogEntry>): void {
    this.writeEntry({ ...extra, level: 'error', event: message });
  }

  private writeEntry(entry: Partial<AuditLogEntry> & { level: LogLevel; event: string }): void {
    if (LOG_LEVELS[entry.level] < this.level) return;

    const { level, event, ...rest } = entry;
    const logEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      level,
      event,
      ...rest
    };

    this.output.write(JSON.stringify(logEntry) + '\n');
  }
}

/**
 * Sanitize path for logging – strip query_param auth secrets.
 */
export function sanitizePathForLog(
  path: string,
  service: ServiceConfig
): string {
  if (service.auth.type === 'query_param') {
    try {
      const url = new URL('http://dummy' + path);
      url.searchParams.delete(
        (service.auth as { type: 'query_param'; param_name: string }).param_name
      );
      const cleaned = url.pathname + url.search;
      return cleaned.endsWith('?') ? cleaned.slice(0, -1) : cleaned;
    } catch {
      return path.split('?')[0] + '?[query redacted]';
    }
  }
  return path;
}
