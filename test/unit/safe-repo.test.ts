import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import childProcess from 'child_process';
import { safeRepo } from '../../src/cli/safe-repo.js';
import { SECRET_SOURCE_FILES } from '../../src/cli/migrate-parsers.js';

// ── Mocks ──

let existsSyncMock: ReturnType<typeof mock.fn>;
let readFileSyncMock: ReturnType<typeof mock.fn>;
let writeFileSyncMock: ReturnType<typeof mock.fn>;
let execSyncMock: ReturnType<typeof mock.fn>;
let stderrOutput: string[];

beforeEach(() => {
  stderrOutput = [];
  mock.method(console, 'error', (...args: any[]) => {
    stderrOutput.push(args.join(' '));
  });
});

afterEach(() => {
  mock.restoreAll();
});

function mockGitRepo(isRepo: boolean) {
  execSyncMock = mock.method(childProcess, 'execSync', (cmd: string, opts?: any) => {
    if (cmd === 'git rev-parse --is-inside-work-tree') {
      if (!isRepo) throw new Error('not a git repo');
      return 'true';
    }
    if (cmd.startsWith('git ls-files --error-unmatch')) {
      throw new Error('not tracked');
    }
    return '';
  });
}

function mockGitRepoWithTracked(trackedFiles: string[]) {
  execSyncMock = mock.method(childProcess, 'execSync', (cmd: string, opts?: any) => {
    if (cmd === 'git rev-parse --is-inside-work-tree') {
      return 'true';
    }
    if (cmd.startsWith('git ls-files --error-unmatch')) {
      const file = cmd.replace('git ls-files --error-unmatch "', '').replace('"', '');
      if (trackedFiles.includes(file)) {
        return file;
      }
      throw new Error('not tracked');
    }
    return '';
  });
}

function mockFs(opts: { exists?: Record<string, boolean>; content?: Record<string, string> }) {
  const existsMap = opts.exists || {};
  const contentMap = opts.content || {};

  existsSyncMock = mock.method(fs, 'existsSync', (p: string) => {
    return existsMap[p] ?? false;
  });

  readFileSyncMock = mock.method(fs, 'readFileSync', (p: string, enc?: string) => {
    if (p in contentMap) return contentMap[p];
    throw new Error(`ENOENT: no such file: ${p}`);
  });

  writeFileSyncMock = mock.method(fs, 'writeFileSync', () => {});
}

// ── Gitignore Updates ──

describe('safe-repo', () => {
  describe('gitignore updates', () => {
    it('no .gitignore exists → created with all entries', () => {
      mockGitRepo(true);
      mockFs({ exists: {} });

      safeRepo();

      assert.equal(writeFileSyncMock.mock.calls.length, 1);
      const written = writeFileSyncMock.mock.calls[0].arguments[1] as string;
      assert.ok(written.startsWith('# Added by keyhole\n'));
      assert.ok(written.includes('.keyhole.*'));
      assert.ok(written.includes('.env'));
      assert.ok(written.includes('localsettings.json'));
      assert.ok(written.includes('.claude/settings.json'));
      assert.ok(written.includes('credentials.json'));

      // .keyhole.* should be first entry after header
      const lines = written.split('\n').filter(l => l && !l.startsWith('#'));
      assert.equal(lines[0], '.keyhole.*');

      assert.ok(stderrOutput.some(l => l.includes('Updated .gitignore')));
    });

    it('empty .gitignore → all entries appended', () => {
      mockGitRepo(true);
      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': '' },
      });

      safeRepo();

      assert.equal(writeFileSyncMock.mock.calls.length, 1);
      const written = writeFileSyncMock.mock.calls[0].arguments[1] as string;
      assert.ok(written.includes('# Added by keyhole'));
      assert.ok(written.includes('.keyhole.*'));
      assert.ok(written.includes('.env'));
    });

    it('some entries present → only missing ones appended', () => {
      mockGitRepo(true);
      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': '# project\nnode_modules/\n.env\n.keyhole.*\n' },
      });

      safeRepo();

      assert.equal(writeFileSyncMock.mock.calls.length, 1);
      const written = writeFileSyncMock.mock.calls[0].arguments[1] as string;

      // .env and .keyhole.* should NOT be in the "added" output (already present)
      const addedLines = stderrOutput.filter(l => l.startsWith('  + '));
      assert.ok(!addedLines.some(l => l.trim() === '+ .env'), '.env should not be re-added');
      assert.ok(!addedLines.some(l => l.trim() === '+ .keyhole.*'), '.keyhole.* should not be re-added');

      // But missing entries should be added
      assert.ok(addedLines.some(l => l.includes('localsettings.json')));
      assert.ok(addedLines.some(l => l.includes('credentials.json')));

      // Existing content preserved
      assert.ok(written.includes('node_modules/'));
    });

    it('all entries present → "already covers" message, file unchanged', () => {
      mockGitRepo(true);

      // Build a .gitignore that has every entry
      const allEntries = ['.keyhole.*', '.env*.local', ...SECRET_SOURCE_FILES];
      const content = allEntries.join('\n') + '\n';

      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': content },
      });

      safeRepo();

      assert.equal(writeFileSyncMock.mock.calls.length, 0, 'file should not be written');
      assert.ok(stderrOutput.some(l => l.includes('already covers')));
    });

    it('second run idempotent → no duplicate entries, no duplicate header', () => {
      mockGitRepo(true);

      // Simulate a .gitignore that was already updated by a previous run
      const firstRunContent =
        'node_modules/\n\n# Added by keyhole\n.keyhole.*\n.env*.local\n' +
        SECRET_SOURCE_FILES.join('\n') + '\n';

      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': firstRunContent },
      });

      safeRepo();

      assert.equal(writeFileSyncMock.mock.calls.length, 0, 'file should not be written on second run');
      assert.ok(stderrOutput.some(l => l.includes('already covers')));
    });

    it('existing unrelated .gitignore content preserved', () => {
      mockGitRepo(true);
      const original = '# my project\nnode_modules/\ndist/\n*.log\n';
      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': original },
      });

      safeRepo();

      const written = writeFileSyncMock.mock.calls[0].arguments[1] as string;
      assert.ok(written.startsWith(original));
    });

    it('.gitignore missing trailing newline → appended block still starts on new line', () => {
      mockGitRepo(true);
      const noTrailingNewline = 'node_modules/\ndist/';
      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': noTrailingNewline },
      });

      safeRepo();

      const written = writeFileSyncMock.mock.calls[0].arguments[1] as string;
      // The file should have a newline inserted before the keyhole block
      assert.ok(!written.includes('dist/\n# Added'), 'should not concatenate directly');
      assert.ok(written.includes('dist/\n\n# Added by keyhole'), 'newline should be added before header');
    });
  });

  // ── Git repo detection ──

  describe('git repo detection', () => {
    it('git rev-parse succeeds → proceeds normally', () => {
      mockGitRepo(true);
      mockFs({ exists: {} });

      safeRepo();

      assert.ok(stderrOutput.some(l => l.includes('Updated .gitignore')));
    });

    it('git rev-parse throws + silent: true → no output, no file changes', () => {
      mockGitRepo(false);
      mockFs({});

      safeRepo({ silent: true });

      assert.equal(writeFileSyncMock.mock.calls.length, 0);
      assert.equal(stderrOutput.length, 0);
    });

    it('git rev-parse throws + silent: false → warning printed', () => {
      mockGitRepo(false);
      mockFs({});

      safeRepo();

      assert.ok(stderrOutput.some(l => l.includes('Not a git repository')));
      assert.equal(writeFileSyncMock.mock.calls.length, 0);
    });
  });

  // ── Already-tracked warnings ──

  describe('already-tracked warnings', () => {
    it('file exists + git ls-files succeeds → warning printed', () => {
      mockGitRepoWithTracked(['.env']);
      mockFs({
        exists: { '.gitignore': true, '.env': true },
        content: { '.gitignore': '' },
      });

      safeRepo();

      assert.ok(stderrOutput.some(l => l.includes('WARNING: .env is already tracked')));
      assert.ok(stderrOutput.some(l => l.includes('git rm --cached .env')));
    });

    it('.keyhole.vault exists + tracked → warning printed', () => {
      mockGitRepoWithTracked(['.keyhole.vault']);
      mockFs({
        exists: { '.gitignore': true, '.keyhole.vault': true },
        content: { '.gitignore': '' },
      });

      safeRepo();

      assert.ok(stderrOutput.some(l => l.includes('WARNING: .keyhole.vault is already tracked')));
      assert.ok(stderrOutput.some(l => l.includes('git rm --cached .keyhole.vault')));
    });

    it('file exists + git ls-files throws → no warning (not tracked)', () => {
      mockGitRepoWithTracked([]);
      mockFs({
        exists: { '.gitignore': true, '.env': true },
        content: { '.gitignore': '' },
      });

      safeRepo();

      assert.ok(!stderrOutput.some(l => l.includes('WARNING')));
    });

    it('file does not exist on disk → no ls-files check attempted', () => {
      mockGitRepoWithTracked(['.env']);
      mockFs({
        exists: { '.gitignore': true },
        content: { '.gitignore': '' },
      });

      safeRepo();

      // .env doesn't exist on disk, so no warning even though it would be "tracked"
      assert.ok(!stderrOutput.some(l => l.includes('WARNING')));
    });

    it('glob entries (.env*.local) → no ls-files check attempted', () => {
      // .env*.local contains a glob char — should be skipped
      mockGitRepoWithTracked(['.env*.local']);
      mockFs({
        exists: { '.gitignore': true, '.env*.local': true },
        content: { '.gitignore': '' },
      });

      safeRepo();

      // Should not try to check glob patterns
      assert.ok(!stderrOutput.some(l => l.includes('WARNING') && l.includes('.env*.local')));
    });
  });
});
