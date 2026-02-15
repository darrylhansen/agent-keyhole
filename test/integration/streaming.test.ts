import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { ResponseMasker, StreamingMasker } from '../../src/sidecar/response-masker.js';
import { SecretRegistry } from '../../src/sidecar/secret-registry.js';
import {
  TEST_SECRET,
  HIGH_ENTROPY_VALUE,
  REDACTION_MARKER,
  makeConfig,
  makeSecretsMap,
} from '../helpers/fixtures.js';
import type { AuthConfig, ParsedConfig } from '../../src/config/schema.js';

/**
 * Integration tests for streaming response masking.
 * Tests the StreamingMasker with real ResponseMasker + SecretRegistry.
 */

function buildStreamingEnv(options?: {
  windowCap?: number;
  heuristic?: boolean;
  jsonPaths?: string[];
  patterns?: string[];
}): { masker: ResponseMasker; config: ParsedConfig } {
  const config = makeConfig({
    github: {
      domains: ['api.github.com'],
      auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
      base_url: 'https://api.github.com',
      response_masking: {
        streaming: 'stream',
        streaming_window_cap: options?.windowCap ?? 200,
        heuristic: { enabled: options?.heuristic ?? true },
        json_paths: options?.jsonPaths,
        patterns: options?.patterns,
      },
    },
  });

  const secrets = makeSecretsMap();
  const registry = new SecretRegistry(secrets, new Set(['KEYHOLE_MANAGED']));
  const masker = new ResponseMasker(config, registry);
  return { masker, config };
}

describe('streaming integration', () => {
  it('secret split across chunks → masked after flush', () => {
    const { masker, config } = buildStreamingEnv();
    const streamer = new StreamingMasker(masker, 'github', config);

    // Split TEST_SECRET across two chunks
    const mid = Math.floor(TEST_SECRET.length / 2);
    const chunk1 = `{"token":"${TEST_SECRET.substring(0, mid)}`;
    const chunk2 = `${TEST_SECRET.substring(mid)}","name":"test"}`;

    const r1 = streamer.processChunk(chunk1);
    const r2 = streamer.processChunk(chunk2);
    const r3 = streamer.flush();

    const combined = r1.output + r2.output + r3.output;
    assert.ok(
      !combined.includes(TEST_SECRET),
      'Secret should not appear in combined streaming output'
    );
    assert.ok(
      combined.includes(REDACTION_MARKER),
      'Redaction marker should be present'
    );
  });

  it('small chunks buffered until window size reached', () => {
    const { masker, config } = buildStreamingEnv();
    const streamer = new StreamingMasker(masker, 'github', config);

    // Send a tiny chunk — should be buffered
    const r1 = streamer.processChunk('ab');
    assert.equal(r1.output, '');

    const r2 = streamer.processChunk('cd');
    assert.equal(r2.output, '');

    // Flush releases the buffer
    const r3 = streamer.flush();
    assert.equal(r3.output.length > 0, true);
  });

  it('secret at exact chunk boundary', () => {
    const { masker, config } = buildStreamingEnv();
    const streamer = new StreamingMasker(masker, 'github', config);

    // Put the secret right at the end of chunk 1
    const prefix = 'data: ';
    const chunk1 = prefix + TEST_SECRET;
    const chunk2 = ' more data follows here';

    const r1 = streamer.processChunk(chunk1);
    const r2 = streamer.processChunk(chunk2);
    const r3 = streamer.flush();

    const combined = r1.output + r2.output + r3.output;
    assert.ok(!combined.includes(TEST_SECRET));
    assert.ok(combined.includes(REDACTION_MARKER));
  });

  it('custom streaming_window_cap honored', () => {
    // Use a very small cap that would be smaller than defaults
    const { masker, config } = buildStreamingEnv({ windowCap: 50 });
    const streamer = new StreamingMasker(masker, 'github', config);

    // With a small window cap, larger chunks should pass through sooner.
    // The window size is max(secretVariantLengths, patternEstimates) + 10.
    // With no patterns and a ~40 char secret, window should be ~50-60.
    const longChunk = 'x'.repeat(200);
    const r1 = streamer.processChunk(longChunk);

    // With window ~50-60, a 200 char chunk should produce ~140+ output
    assert.ok(r1.output.length > 100, `Expected >100 chars output, got ${r1.output.length}`);
  });

  it('L3 heuristic deferred to flush (full JSON)', () => {
    const { masker, config } = buildStreamingEnv({ heuristic: true });
    const streamer = new StreamingMasker(masker, 'github', config);

    // Build a JSON response with a heuristic-triggering field
    const jsonStr = JSON.stringify({
      access_token: HIGH_ENTROPY_VALUE,
      name: 'test',
    });

    // Send it in small chunks that aren't valid JSON individually
    const chunkSize = 20;
    for (let i = 0; i < jsonStr.length; i += chunkSize) {
      streamer.processChunk(jsonStr.substring(i, i + chunkSize));
    }

    // On flush, the full accumulated response is parsed as JSON and
    // the heuristic detector runs on the access_token field
    const result = streamer.flush();
    assert.ok(
      !result.output.includes(HIGH_ENTROPY_VALUE),
      'Heuristic should redact access_token on flush'
    );
    assert.ok(
      result.output.includes(REDACTION_MARKER),
      'Redaction marker should be present after flush'
    );
  });

  it('L4 json_paths deferred to flush', () => {
    const { masker, config } = buildStreamingEnv({
      jsonPaths: ['$.credentials.token'],
      heuristic: false,
    });
    const streamer = new StreamingMasker(masker, 'github', config);

    const jsonStr = JSON.stringify({
      credentials: { token: 'some-value-to-redact-by-path' },
      public: 'visible',
    });

    // Stream in chunks
    const mid = Math.floor(jsonStr.length / 2);
    streamer.processChunk(jsonStr.substring(0, mid));
    streamer.processChunk(jsonStr.substring(mid));
    const result = streamer.flush();

    assert.ok(!result.output.includes('some-value-to-redact-by-path'));
    assert.ok(result.output.includes(REDACTION_MARKER));
  });

  it('L4 patterns applied per-chunk in emitted safe region', () => {
    const { masker, config } = buildStreamingEnv({
      patterns: ['ghp_[a-zA-Z0-9]{36}'],
      heuristic: false,
    });
    const streamer = new StreamingMasker(masker, 'github', config);

    // Use a long prefix so the secret falls in the safe region emitted by
    // processChunk (not deferred to flush). The window size is ~50-60 chars,
    // so a 300-char prefix ensures the secret is well within the emitted part.
    const longPrefix = 'x'.repeat(300);
    const data = `${longPrefix} token: ${TEST_SECRET} end`;
    const chunkResult = streamer.processChunk(data);

    // The safe region emitted by processChunk should have the pattern redacted
    assert.ok(chunkResult.output.length > 0, 'processChunk should emit output');
    assert.ok(
      !chunkResult.output.includes(TEST_SECRET),
      'Pattern should be applied per-chunk on emitted safe region'
    );

    const flushResult = streamer.flush();
    const combined = chunkResult.output + flushResult.output;
    assert.ok(!combined.includes(TEST_SECRET));
  });
});
