import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import {
  isSecretKeyName,
  isSecretValue,
  toSecretRef,
  detectSecrets,
  findDuplicates,
} from '../../src/cli/migrate-detect.js';
import { parseEnvFile, parseJsonFile } from '../../src/cli/migrate-parsers.js';
import type { ExtractedEntry } from '../../src/cli/migrate-parsers.js';
import { WITH_SDK_ENV_CONFIG } from '../helpers/fixtures.js';

// ── Mock fs.readFileSync for parser tests ──

let readFileMock: ReturnType<typeof mock.fn>;

function mockFileContent(content: string) {
  readFileMock = mock.method(fs, 'readFileSync', () => content);
}

afterEach(() => {
  readFileMock?.mock?.restore();
});

describe('migrate-parsers', () => {
  describe('parseEnvFile', () => {
    it('parses KEY=value', () => {
      mockFileContent('DATABASE_URL=postgres://localhost/db\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries.length, 1);
      assert.equal(entries[0].key, 'DATABASE_URL');
      assert.equal(entries[0].value, 'postgres://localhost/db');
      assert.equal(entries[0].quoteStyle, 'none');
    });

    it('parses double-quoted values', () => {
      mockFileContent('API_KEY="my-secret-key"\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries[0].value, 'my-secret-key');
      assert.equal(entries[0].quoteStyle, 'double');
    });

    it('parses single-quoted values', () => {
      mockFileContent("TOKEN='abc123def'\n");
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries[0].value, 'abc123def');
      assert.equal(entries[0].quoteStyle, 'single');
    });

    it('parses export prefix', () => {
      mockFileContent('export SECRET_KEY=myvalue\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries[0].key, 'SECRET_KEY');
      assert.equal(entries[0].value, 'myvalue');
      assert.equal(entries[0].hasExport, true);
    });

    it('skips comments', () => {
      mockFileContent('# This is a comment\nKEY=value\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries.length, 1);
      assert.equal(entries[0].key, 'KEY');
    });

    it('handles trailing comments (unquoted)', () => {
      mockFileContent('KEY=value # this is a comment\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries[0].value, 'value');
    });

    it('handles multiline double-quoted values', () => {
      mockFileContent('CERT="line1\nline2\nline3"\nOTHER=val\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries[0].key, 'CERT');
      assert.equal(entries[0].value, 'line1\nline2\nline3');
    });

    it('skips empty lines', () => {
      mockFileContent('\n\nKEY=value\n\n');
      const entries = parseEnvFile('/fake/.env');
      assert.equal(entries.length, 1);
    });
  });

  describe('parseJsonFile', () => {
    it('extracts top-level keys', () => {
      mockFileContent(JSON.stringify({ TOKEN: 'abc', PORT: '3000' }));
      const entries = parseJsonFile('/fake/settings.json');
      assert.equal(entries.length, 2);
      assert.equal(entries[0].key, 'TOKEN');
      assert.equal(entries[0].value, 'abc');
    });

    it('extracts nested keys with dot paths', () => {
      mockFileContent(JSON.stringify({ config: { secret: 'val' } }));
      const entries = parseJsonFile('/fake/settings.json');
      assert.equal(entries[0].key, 'config.secret');
      assert.equal(entries[0].value, 'val');
    });

    it('extracts from jsonRoot', () => {
      mockFileContent(JSON.stringify({ Values: { DB_URL: 'postgres://...' } }));
      const entries = parseJsonFile('/fake/localsettings.json', 'Values');
      assert.equal(entries.length, 1);
      assert.equal(entries[0].key, 'Values.DB_URL');
      assert.equal(entries[0].value, 'postgres://...');
    });

    it('recursive discovery at any depth', () => {
      mockFileContent(JSON.stringify({
        a: { b: { c: { deep_secret: 'val' } } }
      }));
      const entries = parseJsonFile('/fake/settings.json');
      assert.equal(entries[0].key, 'a.b.c.deep_secret');
    });
  });
});

describe('migrate-detect', () => {
  describe('isSecretKeyName', () => {
    it('matches suspicious patterns', () => {
      assert.equal(isSecretKeyName('GITHUB_TOKEN'), true);
      assert.equal(isSecretKeyName('API_KEY'), true);
      assert.equal(isSecretKeyName('SECRET_KEY'), true);
      assert.equal(isSecretKeyName('access_token'), true);
      assert.equal(isSecretKeyName('DB_PASSWORD'), true);
    });

    it('matches suffix patterns', () => {
      assert.equal(isSecretKeyName('MY_CUSTOM_TOKEN'), true);
      assert.equal(isSecretKeyName('AWS_SECRET'), true);
      assert.equal(isSecretKeyName('STRIPE_API_KEY'), true);
    });

    it('non-suspicious keys return false', () => {
      assert.equal(isSecretKeyName('PORT'), false);
      assert.equal(isSecretKeyName('NODE_ENV'), false);
      assert.equal(isSecretKeyName('LOG_LEVEL'), false);
      assert.equal(isSecretKeyName('HOST'), false);
    });
  });

  describe('isSecretValue', () => {
    it('short values (<=8) excluded', () => {
      assert.equal(isSecretValue('abc'), false);
      assert.equal(isSecretValue('12345678'), false); // exactly 8, <=8 is false
    });

    it('boolean/numeric excluded', () => {
      assert.equal(isSecretValue('true'), false);
      assert.equal(isSecretValue('false'), false);
      assert.equal(isSecretValue('3000'), false);
      assert.equal(isSecretValue('3.14159'), false);
    });

    it('KEYHOLE_MANAGED excluded', () => {
      assert.equal(isSecretValue('KEYHOLE_MANAGED'), false);
    });

    it('URLs without credentials not secret', () => {
      assert.equal(isSecretValue('https://api.example.com/v1'), false);
    });

    it('URLs with embedded credentials detected', () => {
      assert.equal(isSecretValue('https://user:pass123@db.example.com'), true);
    });

    it('long alphanumeric values are secret', () => {
      assert.equal(isSecretValue('ghp_FAKEFAKEFAKEFAKEFAKE'), true);
    });
  });

  describe('toSecretRef', () => {
    it('GITHUB_TOKEN → github-token', () => {
      assert.equal(toSecretRef('GITHUB_TOKEN'), 'github-token');
    });

    it('Values.DATABASE_URL → values-database-url', () => {
      assert.equal(toSecretRef('Values.DATABASE_URL'), 'values-database-url');
    });

    it('strips leading/trailing hyphens', () => {
      assert.equal(toSecretRef('_LEADING_'), 'leading');
    });

    it('collapses consecutive hyphens', () => {
      assert.equal(toSecretRef('SOME__KEY'), 'some-key');
    });
  });

  describe('detectSecrets', () => {
    function makeEntry(key: string, value: string): ExtractedEntry {
      return {
        key,
        value,
        file: '.env',
        line: 1,
        rawLine: `${key}=${value}`,
        quoteStyle: 'none',
        hasExport: false,
        format: 'env',
      };
    }

    it('both signals required: suspicious key + secret value', () => {
      const entries = [
        makeEntry('GITHUB_TOKEN', 'ghp_FAKEFAKEFAKEFAKEFAKE'),
        makeEntry('PORT', '3000'),
        makeEntry('NODE_ENV', 'production'),
      ];
      const results = detectSecrets(entries);
      const secrets = results.filter((r) => r.isSecret);
      assert.equal(secrets.length, 1);
      assert.equal(secrets[0].entry.key, 'GITHUB_TOKEN');
    });

    it('PORT=3000 → skipped', () => {
      const results = detectSecrets([makeEntry('PORT', '3000')]);
      assert.equal(results[0].isSecret, false);
    });

    it('NODE_ENV=production → skipped', () => {
      const results = detectSecrets([makeEntry('NODE_ENV', 'production')]);
      assert.equal(results[0].isSecret, false);
    });

    it('service matching via sdk_env', () => {
      const entries = [
        makeEntry('GITHUB_TOKEN', 'ghp_FAKEFAKEFAKEFAKEFAKE'),
      ];
      const results = detectSecrets(entries, WITH_SDK_ENV_CONFIG);
      const secret = results.find((r) => r.isSecret);
      assert.ok(secret);
      assert.equal(secret.matchedService, 'github');
      assert.equal(secret.secretRef, 'github-token');
    });

    it('unmatched secrets get generated secret_ref from key name', () => {
      const entries = [
        makeEntry('STRIPE_SECRET_KEY', 'sk_live_FAKEFAKEFAKEFAKE'),
      ];
      const results = detectSecrets(entries, WITH_SDK_ENV_CONFIG);
      const secret = results.find((r) => r.isSecret);
      assert.ok(secret);
      assert.equal(secret.matchedService, null);
      assert.equal(secret.secretRef, 'stripe-secret-key');
    });
  });

  describe('findDuplicates', () => {
    it('returns only refs appearing in multiple files', () => {
      const entries = [
        { entry: { key: 'TOKEN', file: '.env' } as ExtractedEntry, secretRef: 'token', matchedService: null, isSecret: true },
        { entry: { key: 'TOKEN', file: '.env.local' } as ExtractedEntry, secretRef: 'token', matchedService: null, isSecret: true },
        { entry: { key: 'OTHER', file: '.env' } as ExtractedEntry, secretRef: 'other', matchedService: null, isSecret: true },
      ];
      const dupes = findDuplicates(entries);
      assert.equal(dupes.size, 1);
      assert.ok(dupes.has('token'));
      assert.equal(dupes.get('token')!.length, 2);
    });

    it('non-secrets excluded from duplicate check', () => {
      const entries = [
        { entry: { key: 'PORT', file: '.env' } as ExtractedEntry, secretRef: 'port', matchedService: null, isSecret: false },
        { entry: { key: 'PORT', file: '.env.local' } as ExtractedEntry, secretRef: 'port', matchedService: null, isSecret: false },
      ];
      const dupes = findDuplicates(entries);
      assert.equal(dupes.size, 0);
    });
  });
});
