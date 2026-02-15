import fs from 'fs';
import path from 'path';

export interface ExtractedEntry {
  key: string;
  value: string;
  file: string;
  line: number;
  /** Original full line text (for .env cleanup) */
  rawLine: string;
  /** 'single' | 'double' | 'none' */
  quoteStyle: 'single' | 'double' | 'none';
  /** true if line had `export ` prefix */
  hasExport: boolean;
  format: 'env' | 'json';
}

export interface SourceFile {
  filename: string;
  format: 'env' | 'json';
  /** JSON-only: dot-separated path to the values object (e.g. "Values") */
  jsonRoot?: string;
}

export const SUPPORTED_FILES: SourceFile[] = [
  { filename: '.env', format: 'env' },
  { filename: '.env.local', format: 'env' },
  { filename: '.env.development', format: 'env' },
  { filename: '.dev.vars', format: 'env' },
  { filename: 'localsettings.json', format: 'json', jsonRoot: 'Values' },
  { filename: '.claude/settings.json', format: 'json' },
];

/**
 * Discover which supported source files exist in the given directory.
 */
export function discoverFiles(dir: string): SourceFile[] {
  const found: SourceFile[] = [];
  for (const sf of SUPPORTED_FILES) {
    const fullPath = path.join(dir, sf.filename);
    if (fs.existsSync(fullPath)) {
      found.push(sf);
    }
  }
  return found;
}

/**
 * Parse a .env-style file and extract key-value pairs.
 */
export function parseEnvFile(filePath: string): ExtractedEntry[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const entries: ExtractedEntry[] = [];
  const filename = path.basename(filePath);

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Handle `export KEY=value`
    let line = trimmed;
    let hasExport = false;
    if (line.startsWith('export ')) {
      hasExport = true;
      line = line.substring(7).trim();
    }

    // Find the = separator
    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) continue;

    const key = line.substring(0, eqIdx).trim();
    if (!key) continue;

    let valuePart = line.substring(eqIdx + 1);

    // Determine quoting and extract value
    let value: string;
    let quoteStyle: 'single' | 'double' | 'none' = 'none';

    if (valuePart.startsWith('"')) {
      quoteStyle = 'double';
      // Handle multiline double-quoted values
      value = extractQuotedValue(valuePart, '"', lines, i);
    } else if (valuePart.startsWith("'")) {
      quoteStyle = 'single';
      value = extractQuotedValue(valuePart, "'", lines, i);
    } else {
      // Unquoted: strip inline comments
      const commentIdx = valuePart.indexOf(' #');
      if (commentIdx !== -1) {
        valuePart = valuePart.substring(0, commentIdx);
      }
      value = valuePart.trim();
    }

    entries.push({
      key,
      value,
      file: filename,
      line: i + 1,
      rawLine,
      quoteStyle,
      hasExport,
      format: 'env',
    });
  }

  return entries;
}

/**
 * Extract a quoted value, handling closing quote and trailing comments.
 */
function extractQuotedValue(
  valuePart: string,
  quote: string,
  lines: string[],
  startLine: number
): string {
  // Remove opening quote
  let inner = valuePart.substring(1);

  // Find closing quote on same line
  const closeIdx = inner.indexOf(quote);
  if (closeIdx !== -1) {
    return inner.substring(0, closeIdx);
  }

  // Multiline: accumulate until closing quote
  const parts = [inner];
  for (let j = startLine + 1; j < lines.length; j++) {
    const nextLine = lines[j];
    const idx = nextLine.indexOf(quote);
    if (idx !== -1) {
      parts.push(nextLine.substring(0, idx));
      break;
    }
    parts.push(nextLine);
  }

  return parts.join('\n');
}

/**
 * Parse a JSON file and extract string key-value pairs.
 * If jsonRoot is specified, only extract from that nested object.
 */
export function parseJsonFile(
  filePath: string,
  jsonRoot?: string
): ExtractedEntry[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const filename = path.basename(filePath);

  let parsed: any;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  // Navigate to the root object if specified
  let target = parsed;
  if (jsonRoot) {
    const parts = jsonRoot.split('.');
    for (const part of parts) {
      if (target && typeof target === 'object' && part in target) {
        target = target[part];
      } else {
        return [];
      }
    }
  }

  const entries: ExtractedEntry[] = [];
  walkJson(target, jsonRoot ? jsonRoot : '', filename, entries);
  return entries;
}

/**
 * Recursively walk a JSON object and extract all string values.
 */
function walkJson(
  obj: any,
  prefix: string,
  filename: string,
  entries: ExtractedEntry[]
): void {
  if (typeof obj !== 'object' || obj === null) return;

  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;

    if (typeof value === 'string') {
      entries.push({
        key: fullKey,
        value,
        file: filename,
        line: 0,
        rawLine: '',
        quoteStyle: 'double',
        hasExport: false,
        format: 'json',
      });
    } else if (typeof value === 'object' && value !== null) {
      walkJson(value, fullKey, filename, entries);
    }
  }
}
