import fs from 'fs';
import type { SecretCandidate } from './migrate-detect.js';

const SCAFFOLD_MARKER = '# ── Scaffolded by';

/**
 * Check whether a stub for this secretRef already exists in the yaml content.
 * Matches:
 * 1. Uncommented secret_ref lines (active services)
 * 2. "# <secretRef>:" inside a scaffold block (previous migration runs)
 *
 * Does NOT match commented template examples (e.g. "  #     secret_ref: openai-api-key").
 */
export function isAlreadyScaffolded(
  yamlContent: string,
  secretRef: string
): boolean {
  // Check 1: uncommented secret_ref line (active service)
  const activePattern = new RegExp(
    `^\\s+secret_ref:\\s*${secretRef}\\s*$`,
    'm'
  );
  if (activePattern.test(yamlContent)) return true;

  // Check 2: scaffolded stub from a previous migration run
  if (
    yamlContent.includes(SCAFFOLD_MARKER) &&
    yamlContent.includes('# ' + secretRef + ':')
  ) {
    return true;
  }

  return false;
}

/**
 * Build a single commented-out service stub block.
 * Indented at 2-space level (inside `services:` block).
 */
export function buildServiceStub(
  c: SecretCandidate,
  isFirst: boolean
): string {
  const lines: string[] = [];

  if (isFirst) {
    lines.push('  # ── Scaffolded by "npx keyhole migrate" ──');
    lines.push(
      '  # TODO: Set the correct domain, auth type, headers if applicable and then uncomment to enable.'
    );
    lines.push('');
  }

  lines.push(`  # ${c.secretRef}:`);
  lines.push('  #   domains:');
  lines.push('  #     - api.example.com');
  lines.push('  #   auth:');
  lines.push('  #     type: bearer');
  lines.push(`  #     secret_ref: ${c.secretRef}`);

  lines.push('');
  return lines.join('\n');
}

/**
 * Find the insertion point inside the `services:` block.
 * Returns the line index where scaffolded stubs should be inserted —
 * after the last active (uncommented) service content, before commented
 * example services.
 *
 * Returns -1 if no reliable insertion point found (caller falls back to EOF).
 */
export function findInsertionPoint(lines: string[]): number {
  let inServices = false;
  let lastActiveLine = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Detect start of services: block
    if (/^services\s*:/.test(trimmed)) {
      inServices = true;
      lastActiveLine = i;
      continue;
    }

    if (!inServices) continue;

    // Top-level key (not indented, not comment, not blank) ends services block
    if (
      trimmed &&
      !trimmed.startsWith('#') &&
      !line.startsWith(' ') &&
      !line.startsWith('\t')
    ) {
      break;
    }

    // Active (non-commented, non-blank) content inside services
    if (trimmed && !trimmed.startsWith('#')) {
      lastActiveLine = i;
    }
  }

  if (lastActiveLine === -1) return -1;

  // Skip past any trailing blank lines after last active content
  let insertAt = lastActiveLine + 1;
  while (insertAt < lines.length && lines[insertAt].trim() === '') {
    insertAt++;
  }
  return insertAt;
}

/**
 * Scaffold commented-out service stubs into keyhole.yaml for unmatched secrets.
 * Stubs are inserted inside the `services:` block at the correct indentation.
 */
export function scaffoldUnmatchedServices(
  configPath: string,
  unmatched: SecretCandidate[]
): { scaffolded: string[]; skipped: string[] } {
  const scaffolded: string[] = [];
  const skipped: string[] = [];

  if (!fs.existsSync(configPath)) {
    for (const c of unmatched) {
      skipped.push(c.secretRef);
    }
    return { scaffolded, skipped };
  }

  const content = fs.readFileSync(configPath, 'utf-8');

  const stubs: string[] = [];
  let isFirst = true;
  for (const c of unmatched) {
    if (isAlreadyScaffolded(content, c.secretRef)) {
      skipped.push(c.secretRef);
      continue;
    }
    stubs.push(buildServiceStub(c, isFirst));
    scaffolded.push(c.secretRef);
    isFirst = false;
  }

  if (stubs.length === 0) {
    return { scaffolded, skipped };
  }

  const stubText = stubs.join('\n');
  const lines = content.split('\n');
  const insertAt = findInsertionPoint(lines);

  if (insertAt === -1) {
    // Fallback: append at end of file
    const separator = content.endsWith('\n') ? '\n' : '\n\n';
    fs.writeFileSync(configPath, content + separator + stubText);
  } else {
    // Ensure blank line before scaffold header for visual separation
    const needsBlankLine =
      insertAt > 0 && lines[insertAt - 1].trim() !== '';
    const prefix = needsBlankLine ? '\n' : '';

    lines.splice(insertAt, 0, prefix + stubText);
    fs.writeFileSync(configPath, lines.join('\n'));
  }

  return { scaffolded, skipped };
}
