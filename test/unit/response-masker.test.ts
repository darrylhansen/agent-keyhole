import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ResponseMasker, StreamingMasker } from '../../src/sidecar/response-masker.js';
import { SecretRegistry } from '../../src/sidecar/secret-registry.js';
import {
  TEST_SECRET,
  TEST_SECRET_B64,
  TEST_SECRET_URL,
  OPENAI_SECRET,
  SHORT_SECRET,
  PLACEHOLDER,
  HIGH_ENTROPY_VALUE,
  JWT_LIKE_TOKEN,
  TEST_UUID,
  REDACTION_MARKER,
  SINGLE_BEARER_CONFIG,
  WITH_HEURISTIC_CONFIG,
  HEURISTIC_DISABLED_CONFIG,
  WITH_L4_CONFIG,
  STREAMING_CONFIG,
  makeConfig,
  makeSecretsMap,
} from '../helpers/fixtures.js';
import type { ParsedConfig } from '../../src/config/schema.js';

function makeMasker(
  config: ParsedConfig = SINGLE_BEARER_CONFIG,
  secrets: Map<string, string> = makeSecretsMap()
): ResponseMasker {
  const placeholders = new Set<string>();
  for (const svc of Object.values(config.services)) {
    placeholders.add(svc.placeholder || PLACEHOLDER);
  }
  const registry = new SecretRegistry(secrets, placeholders);
  return new ResponseMasker(config, registry);
}

describe('ResponseMasker', () => {
  // ── L1: Header Scrubbing ──

  describe('L1 header scrubbing', () => {
    it('removes all sensitive headers', () => {
      const masker = makeMasker();
      const headers = {
        'authorization': 'Bearer secret',
        'set-cookie': 'session=abc',
        'x-api-key': 'key123',
        'x-csrf-token': 'csrf',
        'content-type': 'application/json',
        'x-request-id': 'req-123',
      };
      const clean = masker.scrubHeaders(headers);
      assert.equal(clean['authorization'], undefined);
      assert.equal(clean['set-cookie'], undefined);
      assert.equal(clean['x-api-key'], undefined);
      assert.equal(clean['x-csrf-token'], undefined);
    });

    it('non-sensitive headers pass through', () => {
      const masker = makeMasker();
      const headers = {
        'content-type': 'application/json',
        'x-request-id': 'req-123',
        'cache-control': 'no-cache',
      };
      const clean = masker.scrubHeaders(headers);
      assert.equal(clean['content-type'], 'application/json');
      assert.equal(clean['x-request-id'], 'req-123');
      assert.equal(clean['cache-control'], 'no-cache');
    });

    it('case-insensitive removal', () => {
      const masker = makeMasker();
      const clean = masker.scrubHeaders({
        'Authorization': 'Bearer x',
        'SET-COOKIE': 'y',
      });
      assert.equal(clean['Authorization'], undefined);
      assert.equal(clean['SET-COOKIE'], undefined);
    });
  });

  // ── L2: Known Secrets (JSON) ──

  describe('L2 known secrets — JSON', () => {
    it('known secret as JSON value is redacted', () => {
      const masker = makeMasker();
      const body = JSON.stringify({ token: TEST_SECRET });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('known_secret'));
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.token, REDACTION_MARKER);
    });

    it('known secret as substring in URL value is replaced', () => {
      const masker = makeMasker();
      const body = JSON.stringify({
        clone_url: `https://api.github.com/repos/user/repo?key=${TEST_SECRET}`,
      });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(!result.body.includes(TEST_SECRET));
      assert.ok(result.body.includes('https://api.github.com'));
    });

    it('base64-encoded secret in value is redacted', () => {
      const masker = makeMasker();
      const body = JSON.stringify({ encoded: TEST_SECRET_B64 });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.encoded, REDACTION_MARKER);
    });

    it('URL-encoded secret in value is redacted', () => {
      const masker = makeMasker();
      const body = JSON.stringify({ encoded: TEST_SECRET_URL });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(!result.body.includes(TEST_SECRET_URL));
    });
  });

  // ── L2: Known Secrets (non-JSON) ──

  describe('L2 known secrets — non-JSON', () => {
    it('known secret in plain text body is redacted', () => {
      const masker = makeMasker();
      const body = `Your API key is: ${TEST_SECRET}\nKeep it safe.`;
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('known_secret'));
      assert.ok(!result.body.includes(TEST_SECRET));
      assert.ok(result.body.includes(REDACTION_MARKER));
    });

    it('known secret in HTML body is redacted', () => {
      const masker = makeMasker();
      const body = `<html><body><p>Token: ${TEST_SECRET}</p></body></html>`;
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(!result.body.includes(TEST_SECRET));
    });
  });

  // ── L3: Heuristic (JSON-only) ──

  describe('L3 heuristic — JSON', () => {
    it('unknown token in access_token field is redacted', () => {
      const masker = makeMasker(WITH_HEURISTIC_CONFIG);
      const body = JSON.stringify({ access_token: HIGH_ENTROPY_VALUE });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('heuristic'));
      assert.ok(result.heuristicKeys.includes('access_token'));
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.access_token, REDACTION_MARKER);
    });

    it('UUID in session_id is NOT redacted', () => {
      const masker = makeMasker(WITH_HEURISTIC_CONFIG);
      const body = JSON.stringify({ session_id: TEST_UUID });
      const result = masker.maskBody(body, 'github');
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.session_id, TEST_UUID);
    });

    it('short token_type "bearer" is NOT redacted', () => {
      const masker = makeMasker(WITH_HEURISTIC_CONFIG);
      const body = JSON.stringify({ token_type: 'bearer' });
      const result = masker.maskBody(body, 'github');
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.token_type, 'bearer');
    });

    it('does not fire on non-JSON responses', () => {
      const masker = makeMasker(WITH_HEURISTIC_CONFIG);
      const body = `access_token=${HIGH_ENTROPY_VALUE}`;
      const result = masker.maskBody(body, 'github');
      // L3 is JSON-only; non-JSON only gets L2. Since HIGH_ENTROPY_VALUE
      // is not a known secret, nothing is redacted.
      assert.ok(!result.layers.includes('heuristic'));
    });

    it('does not fire on values already touched by L2', () => {
      const masker = makeMasker(WITH_HEURISTIC_CONFIG);
      // access_token contains a known secret — L2 handles it, L3 should skip
      const body = JSON.stringify({ access_token: TEST_SECRET });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('known_secret'));
      // L3 should NOT also fire since L2 already replaced the value
      assert.ok(!result.heuristicKeys.includes('access_token'));
    });

    it('heuristic disabled via config is not applied', () => {
      const masker = makeMasker(HEURISTIC_DISABLED_CONFIG);
      const body = JSON.stringify({ access_token: HIGH_ENTROPY_VALUE });
      const result = masker.maskBody(body, 'github');
      assert.ok(!result.layers.includes('heuristic'));
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.access_token, HIGH_ENTROPY_VALUE);
    });
  });

  // ── L4: User Overrides ──

  describe('L4 user overrides', () => {
    it('patterns work after L2/L3', () => {
      const masker = makeMasker(WITH_L4_CONFIG);
      // Pattern matches ghp_ + 36 alphanumeric
      const fakeToken = 'ghp_' + 'x'.repeat(36);
      const body = JSON.stringify({ other_field: fakeToken });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('pattern'));
      assert.ok(!result.body.includes(fakeToken));
    });

    it('json_paths work after L2/L3', () => {
      const masker = makeMasker(WITH_L4_CONFIG);
      const body = JSON.stringify({
        credentials: { access_token: 'some-value-here' },
      });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('json_path'));
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.credentials.access_token, REDACTION_MARKER);
    });
  });

  // ── Combined + Edge Cases ──

  describe('combined pipeline and edge cases', () => {
    it('response with multiple layers triggered — all applied in order', () => {
      // Config with L4 pattern + json_path + heuristic
      const config = makeConfig({
        github: {
          domains: ['api.github.com'],
          auth: { type: 'bearer' as const, secret_ref: 'github-token' },
          base_url: 'https://api.github.com',
          response_masking: {
            patterns: ['leak_[a-f0-9]{8}'],
            json_paths: ['$.nested.secret_path'],
            heuristic: { enabled: true },
          },
        },
      });
      const masker = makeMasker(config);

      const body = JSON.stringify({
        token: TEST_SECRET,                       // L2 known
        access_token: HIGH_ENTROPY_VALUE,          // L3 heuristic
        nested: { secret_path: 'will-be-redacted' }, // L4 json_path
        log: 'prefix leak_abcdef01 suffix',        // L4 pattern
      });
      const result = masker.maskBody(body, 'github');
      assert.equal(result.redacted, true);
      assert.ok(result.layers.includes('known_secret'));
      assert.ok(result.layers.includes('heuristic'));
      assert.ok(result.layers.includes('json_path'));
      assert.ok(result.layers.includes('pattern'));
    });

    it('placeholder values (KEYHOLE_MANAGED) are NOT redacted', () => {
      const masker = makeMasker();
      const body = JSON.stringify({ token: PLACEHOLDER });
      const result = masker.maskBody(body, 'github');
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.token, PLACEHOLDER);
    });

    it('short secrets (<8 chars) skipped in L2', () => {
      const secrets = new Map([['short-ref', SHORT_SECRET]]);
      const registry = new SecretRegistry(secrets, new Set([PLACEHOLDER]));
      const masker = new ResponseMasker(SINGLE_BEARER_CONFIG, registry);
      const body = JSON.stringify({ data: SHORT_SECRET });
      const result = masker.maskBody(body, 'github');
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.data, SHORT_SECRET);
    });

    it('maskBody return includes layers and heuristicKeys arrays', () => {
      const masker = makeMasker();
      const body = JSON.stringify({ safe: 'nothing sensitive' });
      const result = masker.maskBody(body, 'github');
      assert.ok(Array.isArray(result.layers));
      assert.ok(Array.isArray(result.heuristicKeys));
      assert.equal(typeof result.body, 'string');
      assert.equal(typeof result.redacted, 'boolean');
    });
  });

  // ── Binary Detection ──

  describe('binary detection', () => {
    it('text Content-Type returns false', () => {
      const masker = makeMasker();
      assert.equal(masker.isBinaryResponse('text/html'), false);
      assert.equal(masker.isBinaryResponse('application/json'), false);
    });

    it('binary Content-Type returns true', () => {
      const masker = makeMasker();
      assert.equal(masker.isBinaryResponse('image/png'), true);
      assert.equal(masker.isBinaryResponse('application/octet-stream'), true);
    });

    it('application/json; charset=utf-8 returns false', () => {
      const masker = makeMasker();
      assert.equal(masker.isBinaryResponse('application/json; charset=utf-8'), false);
    });

    it('null bytes in buffer returns true', () => {
      const masker = makeMasker();
      const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x0d, 0x0a]);
      assert.equal(masker.isBinaryResponse('', buf), true);
    });

    it('printable chars in buffer returns false', () => {
      const masker = makeMasker();
      const buf = Buffer.from('Hello, world!', 'utf-8');
      assert.equal(masker.isBinaryResponse('', buf), false);
    });
  });

  // ── StreamingMasker ──

  describe('StreamingMasker', () => {
    it('secret split across chunks is masked in combined output', () => {
      const masker = makeMasker(STREAMING_CONFIG);
      const sm = new StreamingMasker(masker, 'github', STREAMING_CONFIG);

      const half = Math.floor(TEST_SECRET.length / 2);
      const prefix = `{"token":"`;
      const chunk1 = prefix + TEST_SECRET.substring(0, half);
      const chunk2 = TEST_SECRET.substring(half) + `"}`;

      const r1 = sm.processChunk(chunk1);
      const r2 = sm.processChunk(chunk2);
      const r3 = sm.flush();

      // Accumulate ALL output — not just flush
      const combined = r1.output + r2.output + r3.output;
      assert.ok(
        !combined.includes(TEST_SECRET),
        'Secret should not appear anywhere in combined streaming output'
      );
    });

    it('small chunks are buffered (processChunk returns empty)', () => {
      const masker = makeMasker(STREAMING_CONFIG);
      const sm = new StreamingMasker(masker, 'github', STREAMING_CONFIG);

      const result = sm.processChunk('tiny');
      assert.equal(result.output, '');
    });

    it('custom streaming_window_cap is honored', () => {
      // STREAMING_CONFIG has streaming_window_cap: 100
      const masker = makeMasker(STREAMING_CONFIG);
      const sm = new StreamingMasker(masker, 'github', STREAMING_CONFIG);

      // Feed a chunk larger than the window — should get partial output
      const bigChunk = 'a'.repeat(500);
      const result = sm.processChunk(bigChunk);
      // Some output should have been emitted (safe region before window)
      assert.ok(result.output.length > 0);
    });
  });
});
