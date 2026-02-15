import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RequestBuilder } from '../../src/sidecar/request-builder.js';
import type { KeyholeRequest } from '../../src/sidecar/ipc-types.js';
import {
  TEST_SECRET,
  OPENAI_SECRET,
  SINGLE_BEARER_CONFIG,
  MULTI_SERVICE_CONFIG,
  QUERY_PARAM_CONFIG,
  BASIC_AUTH_CONFIG,
  BASIC_AUTH_NO_USER_CONFIG,
  CUSTOM_HEADER_CONFIG,
  WITH_HEADERS_CONFIG,
  makeSecretsMap,
} from '../helpers/fixtures.js';

function makeRequest(overrides: Partial<KeyholeRequest> = {}): KeyholeRequest {
  return {
    id: 'test-req-1',
    ott: 'test-ott',
    service: 'github',
    method: 'GET',
    path: '/user',
    headers: {},
    bodyEncoding: 'utf8' as const,
    ...overrides,
  };
}

describe('RequestBuilder', () => {
  describe('auth injection', () => {
    it('bearer auth sets Authorization: Bearer <secret>', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const { options } = builder.build(makeRequest());
      const headers = options.headers as Record<string, string>;
      assert.equal(headers['Authorization'], `Bearer ${TEST_SECRET}`);
    });

    it('basic auth with username sets Authorization: Basic base64(user:secret)', () => {
      const secrets = makeSecretsMap({ 'jira-token': TEST_SECRET });
      const builder = new RequestBuilder(BASIC_AUTH_CONFIG, secrets);
      const { options } = builder.build(makeRequest({ service: 'jira', path: '/rest/api' }));
      const headers = options.headers as Record<string, string>;
      const expected = `Basic ${Buffer.from(`user@example.com:${TEST_SECRET}`).toString('base64')}`;
      assert.equal(headers['Authorization'], expected);
    });

    it('basic auth without username sets Authorization: Basic base64(secret:)', () => {
      const secrets = makeSecretsMap({ 'example-token': TEST_SECRET });
      const builder = new RequestBuilder(BASIC_AUTH_NO_USER_CONFIG, secrets);
      const { options } = builder.build(makeRequest({ service: 'service', path: '/api' }));
      const headers = options.headers as Record<string, string>;
      const expected = `Basic ${Buffer.from(`${TEST_SECRET}:`).toString('base64')}`;
      assert.equal(headers['Authorization'], expected);
    });

    it('query_param auth appends secret to URL', () => {
      const secrets = makeSecretsMap({ 'maps-key': TEST_SECRET });
      const builder = new RequestBuilder(QUERY_PARAM_CONFIG, secrets);
      const { url } = builder.build(makeRequest({ service: 'maps', path: '/geocode' }));
      const parsed = new URL(url);
      assert.equal(parsed.searchParams.get('key'), TEST_SECRET);
    });

    it('custom_header auth sets the specified header', () => {
      const secrets = makeSecretsMap({ 'custom-key': TEST_SECRET });
      const builder = new RequestBuilder(CUSTOM_HEADER_CONFIG, secrets);
      const { options } = builder.build(makeRequest({ service: 'custom', path: '/api' }));
      const headers = options.headers as Record<string, string>;
      assert.equal(headers['X-Custom-Key'], TEST_SECRET);
    });
  });

  describe('header handling', () => {
    it('service-specific headers from config are added', () => {
      const builder = new RequestBuilder(WITH_HEADERS_CONFIG, makeSecretsMap());
      const { options } = builder.build(makeRequest());
      const headers = options.headers as Record<string, string>;
      assert.equal(headers['X-GitHub-Api-Version'], '2022-11-28');
      assert.equal(headers['Accept'], 'application/vnd.github+json');
    });

    it('User-Agent: agent-keyhole/1.0 is always set', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const { options } = builder.build(makeRequest());
      const headers = options.headers as Record<string, string>;
      assert.equal(headers['User-Agent'], 'agent-keyhole/1.0');
    });

    it('only Content-Type and Accept are forwarded from agent', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const { options } = builder.build(
        makeRequest({
          headers: {
            'content-type': 'application/json',
            'accept': 'text/html',
            'x-custom': 'should-be-stripped',
            'authorization': 'should-be-stripped',
          },
        })
      );
      const headers = options.headers as Record<string, string>;
      assert.equal(headers['Content-Type'], 'application/json');
      assert.equal(headers['Accept'], 'text/html');
      assert.equal(headers['x-custom'], undefined);
      // Agent's authorization should NOT be forwarded (builder injects its own)
      assert.ok(!headers['authorization']);
    });
  });

  describe('body handling', () => {
    it('binary body decoded from Base64 back to raw bytes', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const { options } = builder.build(
        makeRequest({
          method: 'POST',
          bodyEncoding: 'base64',
          bodyBase64: pngBytes.toString('base64'),
        })
      );
      assert.ok(Buffer.isBuffer(options.body));
      assert.deepEqual(options.body, pngBytes);
    });

    it('text body passed as-is', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const { options } = builder.build(
        makeRequest({
          method: 'POST',
          body: '{"name":"test"}',
        })
      );
      assert.equal(options.body, '{"name":"test"}');
    });
  });

  describe('redirect helpers', () => {
    it('buildAuthHeaders returns correct auth headers for bearer', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const headers = builder.buildAuthHeaders('github');
      assert.equal(headers['Authorization'], `Bearer ${TEST_SECRET}`);
    });

    it('buildAuthHeaders returns empty for unknown service', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const headers = builder.buildAuthHeaders('nonexistent');
      assert.deepEqual(headers, {});
    });

    it('injectQueryParamAuth modifies URL for query_param service', () => {
      const secrets = makeSecretsMap({ 'maps-key': TEST_SECRET });
      const builder = new RequestBuilder(QUERY_PARAM_CONFIG, secrets);
      const url = new URL('https://maps.googleapis.com/geocode');
      builder.injectQueryParamAuth(url, 'maps');
      assert.equal(url.searchParams.get('key'), TEST_SECRET);
    });

    it('injectQueryParamAuth is no-op for non-query_param service', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const url = new URL('https://api.github.com/user');
      builder.injectQueryParamAuth(url, 'github');
      assert.equal(url.search, '');
    });
  });

  describe('error handling', () => {
    it('unknown service throws', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      assert.throws(
        () => builder.build(makeRequest({ service: 'nonexistent' })),
        /Unknown service/
      );
    });

    it('missing secret throws', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, new Map());
      assert.throws(
        () => builder.build(makeRequest()),
        /Secret not resolved/
      );
    });
  });

  describe('URL construction', () => {
    it('builds correct URL from base_url + path', () => {
      const builder = new RequestBuilder(SINGLE_BEARER_CONFIG, makeSecretsMap());
      const { url } = builder.build(makeRequest({ path: '/repos/user/repo' }));
      assert.equal(url, 'https://api.github.com/repos/user/repo');
    });

    it('strips trailing slash from base_url before appending path', () => {
      const config = {
        ...SINGLE_BEARER_CONFIG,
        services: {
          github: {
            ...SINGLE_BEARER_CONFIG.services.github,
            base_url: 'https://api.github.com/',
          },
        },
      };
      // Need to copy _domainToService and _secretRefs
      (config as any)._domainToService = SINGLE_BEARER_CONFIG._domainToService;
      (config as any)._secretRefs = SINGLE_BEARER_CONFIG._secretRefs;
      const builder = new RequestBuilder(config as any, makeSecretsMap());
      const { url } = builder.build(makeRequest({ path: '/user' }));
      assert.equal(url, 'https://api.github.com/user');
    });
  });
});
