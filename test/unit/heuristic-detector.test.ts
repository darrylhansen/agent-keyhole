import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  shannonEntropy,
  isSuspiciousKeyName,
  isExcludedPattern,
  isHighEntropyValue,
  shouldRedactHeuristic,
  HEURISTIC_MIN_LENGTH,
  HEURISTIC_MIN_ENTROPY,
} from '../../src/sidecar/heuristic-detector.js';
import {
  HIGH_ENTROPY_VALUE,
  LOW_ENTROPY_VALUE,
  JWT_LIKE_TOKEN,
  TEST_UUID,
  TEST_OBJECT_ID,
  TEST_URL,
  TEST_TIMESTAMP,
  TEST_EMAIL,
} from '../helpers/fixtures.js';

describe('heuristic-detector', () => {
  describe('isSuspiciousKeyName', () => {
    it('exact matches: token, secret, api_key', () => {
      assert.equal(isSuspiciousKeyName('token'), true);
      assert.equal(isSuspiciousKeyName('secret'), true);
      assert.equal(isSuspiciousKeyName('api_key'), true);
      assert.equal(isSuspiciousKeyName('password'), true);
      assert.equal(isSuspiciousKeyName('access_token'), true);
    });

    it('substring match: x_api_key_v2 matches api_key', () => {
      assert.equal(isSuspiciousKeyName('x_api_key_v2'), true);
      assert.equal(isSuspiciousKeyName('my_secret_value'), true);
    });

    it('case-insensitive: API_KEY, Api_Key', () => {
      assert.equal(isSuspiciousKeyName('API_KEY'), true);
      assert.equal(isSuspiciousKeyName('Api_Key'), true);
      assert.equal(isSuspiciousKeyName('ACCESS_TOKEN'), true);
    });

    it('additional custom key names merged with built-in list', () => {
      assert.equal(isSuspiciousKeyName('x_custom_header'), false);
      assert.equal(
        isSuspiciousKeyName('x_custom_header', ['x_custom_header']),
        true
      );
    });

    it('non-suspicious keys return false', () => {
      assert.equal(isSuspiciousKeyName('name'), false);
      assert.equal(isSuspiciousKeyName('id'), false);
      assert.equal(isSuspiciousKeyName('url'), false);
      assert.equal(isSuspiciousKeyName('count'), false);
      assert.equal(isSuspiciousKeyName('status'), false);
      assert.equal(isSuspiciousKeyName('description'), false);
    });
  });

  describe('shannonEntropy', () => {
    it('low entropy string ("aaaaaaa") returns low value', () => {
      const e = shannonEntropy('aaaaaaa');
      assert.ok(e < 1.0, `Expected < 1.0, got ${e}`);
    });

    it('high entropy string (random hex) returns high value', () => {
      const e = shannonEntropy(HIGH_ENTROPY_VALUE);
      assert.ok(e > HEURISTIC_MIN_ENTROPY, `Expected > ${HEURISTIC_MIN_ENTROPY}, got ${e}`);
    });
  });

  describe('isHighEntropyValue', () => {
    it('short string (<=16 chars) returns false regardless of entropy', () => {
      // 16 chars of high entropy — still below length threshold
      const shortHigh = HIGH_ENTROPY_VALUE.substring(0, 16);
      assert.equal(isHighEntropyValue(shortHigh), false);
    });

    it('long low-entropy string returns false', () => {
      assert.equal(isHighEntropyValue(LOW_ENTROPY_VALUE), false);
    });

    it('long high-entropy string returns true', () => {
      assert.equal(isHighEntropyValue(HIGH_ENTROPY_VALUE), true);
    });

    it('respects custom minLength', () => {
      // HIGH_ENTROPY_VALUE is 64 chars, passes default minLength=16
      assert.equal(isHighEntropyValue(HIGH_ENTROPY_VALUE), true);
      // Custom minLength=100 — should fail (value is 64 chars, 64 <= 100)
      assert.equal(isHighEntropyValue(HIGH_ENTROPY_VALUE, 100), false);
    });
  });

  describe('isExcludedPattern', () => {
    it('UUID is excluded', () => {
      assert.equal(isExcludedPattern(TEST_UUID), true);
    });

    it('MongoDB ObjectID (24 hex chars) is excluded', () => {
      assert.equal(isExcludedPattern(TEST_OBJECT_ID), true);
    });

    it('URL is excluded', () => {
      assert.equal(isExcludedPattern(TEST_URL), true);
    });

    it('ISO timestamp is excluded', () => {
      assert.equal(isExcludedPattern(TEST_TIMESTAMP), true);
    });

    it('Email is excluded', () => {
      assert.equal(isExcludedPattern(TEST_EMAIL), true);
    });

    it('random hex string is NOT excluded', () => {
      assert.equal(isExcludedPattern(HIGH_ENTROPY_VALUE), false);
    });
  });

  describe('shouldRedactHeuristic', () => {
    it('suspicious key + high-entropy value returns true', () => {
      assert.equal(shouldRedactHeuristic('access_token', HIGH_ENTROPY_VALUE), true);
    });

    it('suspicious key + low-entropy value returns false (Signal B fails)', () => {
      assert.equal(shouldRedactHeuristic('access_token', LOW_ENTROPY_VALUE), false);
    });

    it('normal key + high-entropy value returns false (Signal A fails)', () => {
      assert.equal(shouldRedactHeuristic('data_payload', HIGH_ENTROPY_VALUE), false);
    });

    it('real-world: OAuth access_token with JWT-like value is redacted', () => {
      assert.equal(shouldRedactHeuristic('access_token', JWT_LIKE_TOKEN), true);
    });

    it('real-world: token_type "bearer" is NOT redacted (too short)', () => {
      assert.equal(shouldRedactHeuristic('token_type', 'bearer'), false);
    });

    it('respects additionalKeyNames option', () => {
      assert.equal(shouldRedactHeuristic('x_custom', HIGH_ENTROPY_VALUE), false);
      assert.equal(
        shouldRedactHeuristic('x_custom', HIGH_ENTROPY_VALUE, {
          additionalKeyNames: ['x_custom'],
        }),
        true
      );
    });
  });
});
