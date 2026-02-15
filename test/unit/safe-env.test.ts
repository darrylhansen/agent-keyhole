import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSafeEnv,
  generateSafeEnvForService,
} from '../../src/client/safe-env.js';
import {
  WITH_SDK_ENV_CONFIG,
  SINGLE_BEARER_CONFIG,
  PLACEHOLDER,
  CUSTOM_PLACEHOLDER,
} from '../helpers/fixtures.js';

describe('safe-env', () => {
  describe('generateSafeEnv', () => {
    it('generates placeholders from all services with sdk_env', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      assert.equal(env['GITHUB_TOKEN'], PLACEHOLDER);
      assert.equal(env['OPENAI_API_KEY'], CUSTOM_PLACEHOLDER);
    });

    it('{{placeholder}} resolved with service placeholder', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      // openai has custom placeholder
      assert.equal(env['OPENAI_API_KEY'], CUSTOM_PLACEHOLDER);
    });

    it('default placeholder is KEYHOLE_MANAGED', () => {
      const env = generateSafeEnv(WITH_SDK_ENV_CONFIG);
      // github has no custom placeholder → defaults to KEYHOLE_MANAGED
      assert.equal(env['GITHUB_TOKEN'], 'KEYHOLE_MANAGED');
    });

    it('services without sdk_env produce no env vars', () => {
      const env = generateSafeEnv(SINGLE_BEARER_CONFIG);
      assert.deepEqual(env, {});
    });
  });

  describe('generateSafeEnvForService', () => {
    it('returns env for named service only', () => {
      const env = generateSafeEnvForService(WITH_SDK_ENV_CONFIG, 'github');
      assert.equal(env['GITHUB_TOKEN'], PLACEHOLDER);
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
