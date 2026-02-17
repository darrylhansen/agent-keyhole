import fs from 'fs';
import { execSync } from 'child_process';
import { SECRET_SOURCE_FILES } from './migrate-parsers.js';

const GITIGNORE_ENTRIES = [
  // Keyhole files
  '.keyhole.*',
  // Framework catch-all for .env.*.local variants
  '.env*.local',
  // All migrate-supported files
  ...SECRET_SOURCE_FILES,
];

function deduplicate(entries: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const entry of entries) {
    if (!seen.has(entry)) {
      seen.add(entry);
      result.push(entry);
    }
  }
  return result;
}

function isGitRepo(): boolean {
  try {
    const result = execSync('git rev-parse --is-inside-work-tree', {
      stdio: 'pipe',
      encoding: 'utf-8',
    });
    return result.trim() === 'true';
  } catch {
    return false;
  }
}

export function safeRepo(options?: { silent?: boolean }): void {
  const silent = options?.silent ?? false;

  if (!isGitRepo()) {
    if (!silent) {
      console.error('⚠ Not a git repository. Nothing to do.');
    }
    return;
  }

  const gitignorePath = '.gitignore';
  const entries = deduplicate(GITIGNORE_ENTRIES);

  let existingContent = '';
  let fileExists = false;

  if (fs.existsSync(gitignorePath)) {
    fileExists = true;
    existingContent = fs.readFileSync(gitignorePath, 'utf-8');
  }

  // Parse existing lines into a Set for matching
  const existingLines = new Set(
    existingContent
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#'))
  );

  // Collect missing entries
  const missing = entries.filter((entry) => !existingLines.has(entry));

  if (missing.length === 0) {
    console.error('✓ .gitignore already covers all sensitive files');
  } else {
    let content = existingContent;

    if (fileExists) {
      // Ensure file ends with newline before appending
      if (content.length > 0 && !content.endsWith('\n')) {
        content += '\n';
      }

      // Check if header already exists
      if (!content.includes('# Added by keyhole')) {
        content += '\n# Added by keyhole\n';
      }
    } else {
      // No .gitignore existed — create with header
      content = '# Added by keyhole\n';
    }

    // Append each missing entry, .keyhole.* first
    const keyholeFirst = missing.filter((e) => e === '.keyhole.*');
    const rest = missing.filter((e) => e !== '.keyhole.*');
    const ordered = [...keyholeFirst, ...rest];

    for (const entry of ordered) {
      content += entry + '\n';
    }

    fs.writeFileSync(gitignorePath, content);

    console.error('Updated .gitignore:');
    for (const entry of ordered) {
      console.error(`  + ${entry}`);
    }
  }

  // Already-tracked file detection
  const trackCheckFiles = [...SECRET_SOURCE_FILES, '.keyhole.vault'];
  const warnings: string[] = [];

  for (const file of trackCheckFiles) {
    // Skip glob patterns (only check literal filenames)
    if (file.includes('*')) continue;

    if (!fs.existsSync(file)) continue;

    try {
      execSync(`git ls-files --error-unmatch "${file}"`, { stdio: 'pipe' });
      // If no error, file is tracked
      warnings.push(file);
    } catch {
      // Not tracked, safe
    }
  }

  for (const file of warnings) {
    console.error(`⚠ WARNING: ${file} is already tracked by Git.`);
    console.error('  Adding it to .gitignore won\'t remove it from history.');
    console.error(`  Run: git rm --cached ${file}`);
  }
}
