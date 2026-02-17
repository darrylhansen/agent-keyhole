import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSafeEnv,
  generateSafeEnvForService,
  generatePlaceholder,
} from '../../src/client/safe-env.js';
import {
  WITH_SDK_ENV_CONFIG,
  SINGLE_BEARER_CONFIG,
  CUSTOM_PLACEHOLDER,
} from '../helpers/fixtures.js';

describe('generatePlaceholder', () => {
  it('extracts ghp_ prefix from github PAT', () => {
    const p = generatePlaceholder('github', 'ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8');
    assert.ok(p.startsWith('ghp_'));
    assert.ok(p.includes('KEYHOLE_MANAGED'));
    assert.equal(p.length, 40);
  });

  it('extracts sk-proj- prefix from OpenAI key', () => {
    const original = 'sk-proj-ABCdef123456GHIjkl789012MNOpqr345678901';
    const p = generatePlaceholder('openai', original);
    assert.ok(p.startsWith('sk-proj-'));
    assert.ok(p.includes('KEYHOLE_MANAGED'));
    assert.equal(p.length, original.length);
  });

  it('extracts sk_test_ prefix from Stripe key', () => {
    const p = generatePlaceholder('stripe', 'sk_test_51Hf8aR3bKxLmN9pQrStUvWxYz0123456789');
    assert.ok(p.startsWith('sk_test_'));
    assert.ok(p.includes('KEYHOLE_MANAGED'));
  });

  it('falls back for secrets with no prefix', () => {
    assert.equal(generatePlaceholder('custom', 'abcdefghijklmnop'), 'custom_KEYHOLE_MANAGED');
  });

  it('uses service name when no original value', () => {
    assert.equal(generatePlaceholder('myapi'), 'myapi_KEYHOLE_MANAGED');
  });

  it('pads result to match original length', () => {
    const original = 'ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8'; // 40 chars
    const p = generatePlaceholder('github', original);
    assert.equal(p.length, original.length);
  });

  it('two services produce different placeholders', () => {
    const a = generatePlaceholder('github');
    const b = generatePlaceholder('openai');
    assert.notEqual(a, b);
  });

  it('extracts sk-ant- prefix from Anthropic key', () => {
    const p = generatePlaceholder('anthropic', 'sk-ant-key01-abcdefghijklmnopqrstuvwxyz0123456789');
    assert.ok(p.startsWith('sk-ant-'));
    assert.ok(p.includes('KEYHOLE_MANAGED'));
  });
});

describe('safe-env', () => {
  describe('generateSafeEnv', () => {
    it('generates placeholders from all services with sdk_env', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      assert.equal(env['GITHUB_TOKEN'], 'github_KEYHOLE_MANAGED');
      assert.equal(env['OPENAI_API_KEY'], CUSTOM_PLACEHOLDER);
    });

    it('{{placeholder}} resolved with service placeholder', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      // openai has custom placeholder
      assert.equal(env['OPENAI_API_KEY'], CUSTOM_PLACEHOLDER);
    });

    it('default placeholder is servicename_KEYHOLE_MANAGED', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      // github has no custom placeholder → defaults to github_KEYHOLE_MANAGED
      assert.equal(env['GITHUB_TOKEN'], 'github_KEYHOLE_MANAGED');
    });

    it('services without sdk_env produce no env vars', () => {
      const env = generateSafeEnv(SINGLE_BEARER_CONFIG);
      assert.deepEqual(env, {});
    });

    it('multiple services → unique placeholder values', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      const values = Object.values(env);
      const unique = new Set(values);
      assert.equal(unique.size, values.length);
    });
  });

  describe('generateSafeEnvForService', () => {
    it('returns env for named service only', () => {
      const env = generateSafeEnvForService(WITH_SDK_ENV_CONFIG, 'github');
      assert.equal(env['GITHUB_TOKEN'], 'github_KEYHOLE_MANAGED');
      assert.equal(env['OPENAI_API_KEY'], undefined);
    });

    it('returns empty for service without sdk_env', () => {
      const env = generateSafeEnvForService(SINGLE_BEARER_CONFIG, 'github');
      assert.deepEqual(env, {});
    });

    it('returns empty for nonexistent service', () => {
      const env = generateSafeEnvForService(WITH_SDK_ENV_CONFIG, 'nonexistent');
      assert.deepEqual(env, {});
    });
  });
});
