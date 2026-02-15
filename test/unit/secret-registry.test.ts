import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SecretRegistry, MIN_SECRET_LENGTH } from '../../src/sidecar/secret-registry.js';
import {
  TEST_SECRET,
  TEST_SECRET_B64,
  TEST_SECRET_URL,
  SECRET_WITH_SPECIAL_CHARS,
  SECRET_WITH_SPECIAL_CHARS_URL,
  SHORT_SECRET,
  PLACEHOLDER,
} from '../helpers/fixtures.js';

describe('SecretRegistry', () => {
  function makeRegistry(
    secrets: Record<string, string> = { 'github-token': TEST_SECRET },
    placeholders: string[] = [PLACEHOLDER]
  ): SecretRegistry {
    return new SecretRegistry(
      new Map(Object.entries(secrets)),
      new Set(placeholders)
    );
  }

  describe('exact matching', () => {
    it('matches plain secret value', () => {
      const reg = makeRegistry();
      assert.equal(reg.hasExact(TEST_SECRET), true);
    });

    it('matches base64-encoded variant', () => {
      const reg = makeRegistry();
      assert.equal(reg.hasExact(TEST_SECRET_B64), true);
    });

    it('matches URL-encoded variant', () => {
      const reg = makeRegistry();
      assert.equal(reg.hasExact(TEST_SECRET_URL), true);
    });

    it('matches URL-encoded variant of secret with special chars', () => {
      // TEST_SECRET has no URL-special chars so TEST_SECRET_URL === TEST_SECRET.
      // This test uses a secret with +, =, / that actually change under encodeURIComponent.
      const reg = makeRegistry({ 'special-key': SECRET_WITH_SPECIAL_CHARS });
      assert.notEqual(SECRET_WITH_SPECIAL_CHARS, SECRET_WITH_SPECIAL_CHARS_URL,
        'Test setup: secret must differ from its URL-encoded form');
      assert.equal(reg.hasExact(SECRET_WITH_SPECIAL_CHARS_URL), true);
    });

    it('no false positive on unrelated strings', () => {
      const reg = makeRegistry();
      assert.equal(reg.hasExact('completely-different-value'), false);
      assert.equal(reg.hasExact('ghp_close_but_not_quite'), false);
    });
  });

  describe('substring matching', () => {
    it('finds secret embedded in URL', () => {
      const reg = makeRegistry();
      const result = reg.findSubstring(`https://api.com?key=${TEST_SECRET}`);
      assert.equal(result, TEST_SECRET);
    });

    it('returns null for unrelated strings', () => {
      const reg = makeRegistry();
      assert.equal(reg.findSubstring('nothing here'), null);
    });

    it('skips scan when input is shorter than minLength', () => {
      const reg = makeRegistry();
      assert.equal(reg.findSubstring('short'), null);
    });
  });

  describe('replaceAllSubstrings', () => {
    it('replaces all occurrences in a value', () => {
      const reg = makeRegistry();
      const input = `first=${TEST_SECRET}&second=${TEST_SECRET}`;
      const { result, replaced } = reg.replaceAllSubstrings(input, '[REDACTED]');
      assert.equal(replaced, true);
      assert.ok(!result.includes(TEST_SECRET));
      assert.equal(result, 'first=[REDACTED]&second=[REDACTED]');
    });

    it('returns unchanged when no match', () => {
      const reg = makeRegistry();
      const { result, replaced } = reg.replaceAllSubstrings('no secrets here', '[REDACTED]');
      assert.equal(replaced, false);
      assert.equal(result, 'no secrets here');
    });

    it('skips scan when input is shorter than minLength', () => {
      const reg = makeRegistry();
      const { result, replaced } = reg.replaceAllSubstrings('short', '[REDACTED]');
      assert.equal(replaced, false);
      assert.equal(result, 'short');
    });
  });

  describe('filtering', () => {
    it('excludes short secrets (< MIN_SECRET_LENGTH)', () => {
      const reg = makeRegistry({ ref: SHORT_SECRET });
      assert.equal(reg.isEmpty(), true);
      assert.equal(reg.hasExact(SHORT_SECRET), false);
    });

    it('excludes placeholder values', () => {
      const reg = makeRegistry({ ref: PLACEHOLDER }, [PLACEHOLDER]);
      assert.equal(reg.isEmpty(), true);
      assert.equal(reg.hasExact(PLACEHOLDER), false);
    });
  });

  describe('empty registry', () => {
    it('no crashes, no matches', () => {
      const reg = new SecretRegistry(new Map(), new Set());
      assert.equal(reg.isEmpty(), true);
      assert.equal(reg.hasExact('anything'), false);
      assert.equal(reg.findSubstring('anything at all'), null);
      const { result, replaced } = reg.replaceAllSubstrings('text', '[R]');
      assert.equal(replaced, false);
      assert.equal(result, 'text');
    });
  });

  describe('getAllVariants / getMinLength', () => {
    it('returns all generated variants', () => {
      const reg = makeRegistry();
      const variants = reg.getAllVariants();
      assert.ok(variants.includes(TEST_SECRET));
      assert.ok(variants.includes(TEST_SECRET_B64));
      // URL-encoded may equal plain for some secrets, but should have at least 2 unique
      assert.ok(variants.length >= 2);
    });

    it('getMinLength returns shortest variant length', () => {
      const reg = makeRegistry();
      const min = reg.getMinLength();
      assert.ok(min <= TEST_SECRET.length);
      assert.ok(min > 0);
    });
  });
});
