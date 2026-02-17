import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import {
  isAlreadyScaffolded,
  buildServiceStub,
  findInsertionPoint,
  scaffoldUnmatchedServices,
} from '../../src/cli/migrate-scaffold.js';
import type { SecretCandidate } from '../../src/cli/migrate-detect.js';
import type { ExtractedEntry } from '../../src/cli/migrate-parsers.js';

// ── Helpers ──

function makeEntry(overrides: Partial<ExtractedEntry> = {}): ExtractedEntry {
  return {
    key: 'STRIPE_SECRET_KEY',
    value: 'sk_test_51Hf8aR3bKxLmN9pQrStUvWxYz',
    file: '.env',
    line: 1,
    rawLine: 'STRIPE_SECRET_KEY=sk_test_51Hf8aR3bKxLmN9pQrStUvWxYz',
    quoteStyle: 'none',
    hasExport: false,
    format: 'env',
    ...overrides,
  };
}

function makeCandidate(
  secretRef: string,
  entryOverrides: Partial<ExtractedEntry> = {}
): SecretCandidate {
  return {
    entry: makeEntry(entryOverrides),
    secretRef,
    matchedService: null,
    isSecret: true,
  };
}

// ── Mock tracking ──

let readFileMock: ReturnType<typeof mock.fn> | undefined;
let writeFileMock: ReturnType<typeof mock.fn> | undefined;
let existsMock: ReturnType<typeof mock.fn> | undefined;

afterEach(() => {
  readFileMock?.mock?.restore();
  writeFileMock?.mock?.restore();
  existsMock?.mock?.restore();
  readFileMock = undefined;
  writeFileMock = undefined;
  existsMock = undefined;
});

// ── isAlreadyScaffolded ──

describe('isAlreadyScaffolded', () => {
  it('returns true when yaml contains uncommented secret_ref: <ref>', () => {
    const yaml = `services:\n  github:\n    auth:\n      secret_ref: openai-api-key\n`;
    assert.equal(isAlreadyScaffolded(yaml, 'openai-api-key'), true);
  });

  it('returns false when secret_ref only appears in a commented template example', () => {
    const yaml = `services:\n  # openai:\n  #   auth:\n  #     secret_ref: openai-api-key\n`;
    assert.equal(isAlreadyScaffolded(yaml, 'openai-api-key'), false);
  });

  it('returns true when # <secretRef>: appears inside a scaffold block', () => {
    const yaml = [
      'services:',
      '  github:',
      '    auth:',
      '      secret_ref: github-token',
      '  # ── Scaffolded by "npx keyhole migrate" ──',
      '  # stripe-secret-key:',
      '  #   auth:',
      '  #     secret_ref: stripe-secret-key',
    ].join('\n');
    assert.equal(isAlreadyScaffolded(yaml, 'stripe-secret-key'), true);
  });

  it('returns false when # <secretRef>: appears without scaffold marker', () => {
    // A manually commented service should not count as scaffolded
    const yaml = `services:\n  github:\n    auth:\n      secret_ref: github-token\n  # stripe-secret-key:\n`;
    assert.equal(isAlreadyScaffolded(yaml, 'stripe-secret-key'), false);
  });

  it('returns false when neither pattern matches', () => {
    const yaml = `services:\n  github:\n    auth:\n      secret_ref: github-token\n`;
    assert.equal(isAlreadyScaffolded(yaml, 'stripe-secret-key'), false);
  });
});

// ── buildServiceStub ──

describe('buildServiceStub', () => {
  it('stub contains secret_ref and api.example.com, no sdk_env', () => {
    const c = makeCandidate('stripe-secret-key', {
      key: 'STRIPE_SECRET_KEY',
      format: 'env',
    });
    const stub = buildServiceStub(c, false);

    assert.ok(stub.includes('secret_ref: stripe-secret-key'));
    assert.ok(stub.includes('api.example.com'));
    assert.ok(!stub.includes('sdk_env'));
  });

  it('json-sourced stub also has no sdk_env', () => {
    const c = makeCandidate('db-connection-string', {
      key: 'ConnectionStrings.Default',
      format: 'json',
      file: 'localsettings.json',
    });
    const stub = buildServiceStub(c, false);

    assert.ok(stub.includes('secret_ref: db-connection-string'));
    assert.ok(stub.includes('api.example.com'));
    assert.ok(!stub.includes('sdk_env'));
  });

  it('all lines have 2-space base indent', () => {
    const c = makeCandidate('stripe-secret-key');
    const stub = buildServiceStub(c, false);
    const lines = stub.split('\n').filter((l) => l.trim() !== '');
    for (const line of lines) {
      assert.ok(
        line.startsWith('  '),
        `Line should start with 2-space indent: "${line}"`
      );
    }
  });
});

// ── scaffoldUnmatchedServices ──

describe('scaffoldUnmatchedServices', () => {
  const SAMPLE_YAML = [
    'services:',
    '  github:',
    '    domains:',
    '      - api.github.com',
    '    auth:',
    '      type: bearer',
    '      secret_ref: github-token',
    '',
    '  # ── Scaffolded by "npx keyhole migrate" ──',
    '  # TODO: Set the correct domain and auth type, then uncomment to enable.',
    '',
    '  # db-connection-string:',
    '  #   domains:',
    '  #     - api.example.com',
    '  #   auth:',
    '  #     type: bearer',
    '  #     secret_ref: db-connection-string',
    '',
    '  # openai:',
    '  #   domains:',
    '  #     - api.openai.com',
    '  #   auth:',
    '  #     type: bearer',
    '  #     secret_ref: openai-api-key',
    '',
  ].join('\n');

  it('inserts stubs inside services block', () => {
    let writtenContent = '';
    existsMock = mock.method(fs, 'existsSync', () => true);
    readFileMock = mock.method(fs, 'readFileSync', () => SAMPLE_YAML);
    writeFileMock = mock.method(
      fs,
      'writeFileSync',
      (_path: string, data: string) => {
        writtenContent = data;
      }
    );

    const candidates = [
      makeCandidate('stripe-secret-key', {
        key: 'STRIPE_SECRET_KEY',
        format: 'env',
      }),
    ];

    const { scaffolded, skipped } = scaffoldUnmatchedServices(
      '/tmp/keyhole.yaml',
      candidates
    );

    assert.deepEqual(scaffolded, ['stripe-secret-key']);
    assert.deepEqual(skipped, []);
    assert.ok(writtenContent.includes('secret_ref: stripe-secret-key'));
    assert.ok(writtenContent.includes('Scaffolded by'));

    // Verify stub appears before the commented openai example
    const stripeIdx = writtenContent.indexOf('# stripe-secret-key:');
    const openaiIdx = writtenContent.indexOf('# openai:');
    assert.ok(
      stripeIdx < openaiIdx,
      'scaffold stub should appear before commented example services'
    );
  });

  it('skips already-scaffolded entries', () => {
    existsMock = mock.method(fs, 'existsSync', () => true);
    readFileMock = mock.method(fs, 'readFileSync', () => SAMPLE_YAML);
    writeFileMock = mock.method(fs, 'writeFileSync', () => {});

    // db-connection-string exists in a scaffold block (marker + # ref:)
    const candidates = [
      makeCandidate('db-connection-string', {
        key: 'DB_CONNECTION_STRING',
        format: 'env',
      }),
    ];

    const { scaffolded, skipped } = scaffoldUnmatchedServices(
      '/tmp/keyhole.yaml',
      candidates
    );

    assert.deepEqual(scaffolded, []);
    assert.deepEqual(skipped, ['db-connection-string']);
    assert.equal(writeFileMock!.mock.callCount(), 0);
  });

  it('no write when all entries already scaffolded', () => {
    existsMock = mock.method(fs, 'existsSync', () => true);
    readFileMock = mock.method(fs, 'readFileSync', () => SAMPLE_YAML);
    writeFileMock = mock.method(fs, 'writeFileSync', () => {});

    // github-token: active service (uncommented secret_ref)
    // db-connection-string: previous scaffold block (marker + # ref:)
    const candidates = [
      makeCandidate('db-connection-string'),
      makeCandidate('github-token'),
    ];

    const { scaffolded, skipped } = scaffoldUnmatchedServices(
      '/tmp/keyhole.yaml',
      candidates
    );

    assert.deepEqual(scaffolded, []);
    assert.equal(skipped.length, 2);
    assert.equal(writeFileMock!.mock.callCount(), 0);
  });

  it('returns all in skipped when config file does not exist', () => {
    existsMock = mock.method(fs, 'existsSync', () => false);

    const candidates = [
      makeCandidate('stripe-secret-key'),
      makeCandidate('db-connection-string'),
    ];

    const { scaffolded, skipped } = scaffoldUnmatchedServices(
      '/tmp/nonexistent.yaml',
      candidates
    );

    assert.deepEqual(scaffolded, []);
    assert.deepEqual(skipped, ['stripe-secret-key', 'db-connection-string']);
  });
});
