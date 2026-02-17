import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { loadConfig } from '../../src/config/loader.js';
import {
  VALID_YAML,
  YAML_MISSING_SERVICES,
  YAML_EMPTY_SERVICES,
  YAML_MISSING_DOMAINS,
  YAML_MISSING_AUTH,
  YAML_INVALID_AUTH_TYPE,
  YAML_DUPLICATE_DOMAIN,
  YAML_UNKNOWN_AGENT_SERVICE,
  YAML_INVALID_JSON_PATH,
  YAML_INVALID_STREAMING_CAP,
  YAML_STREAMING_CAP_FLOAT,
  YAML_INVALID_BASE_URL,
  YAML_LOCALHOST_AUTO_HTTP,
  YAML_REMOTE_AUTO_HTTPS,
  YAML_INVALID_SDK_ENV_TEMPLATE,
  YAML_QUERY_PARAM_MISSING_NAME,
  YAML_CUSTOM_HEADER_MISSING_NAME,
  YAML_UNBOUNDED_PATTERN,
  YAML_HEURISTIC_CONFIG,
  YAML_INVALID_HEURISTIC_CONFIG,
  YAML_WITH_AGENTS,
  YAML_MULTI_SERVICE,
} from '../helpers/fixtures.js';

// Mock fs.readFileSync so we don't need real files
let readFileMock: ReturnType<typeof mock.fn>;

function mockYaml(content: string) {
  readFileMock = mock.method(fs, 'readFileSync', () => content);
}

afterEach(() => {
  readFileMock?.mock?.restore();
});

describe('config-loader', () => {
  describe('valid config', () => {
    it('valid YAML parses correctly', async () => {
      mockYaml(VALID_YAML);
      const config = await loadConfig('/fake/keyhole.yaml');
      assert.ok(config.services.github);
      assert.equal(config.services.github.auth.type, 'bearer');
      assert.equal(config.services.github.auth.secret_ref, 'github-token');
      assert.ok(config._domainToService instanceof Map);
      assert.equal(config._domainToService.get('api.github.com'), 'github');
      assert.ok(Array.isArray(config._secretRefs));
      assert.ok(config._secretRefs.includes('github-token'));
    });
  });

  describe('validation errors', () => {
    it('missing services section throws', async () => {
      mockYaml(YAML_MISSING_SERVICES);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /services/);
    });

    it('missing domains throws', async () => {
      mockYaml(YAML_MISSING_DOMAINS);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /domain/i);
    });

    it('missing auth throws', async () => {
      mockYaml(YAML_MISSING_AUTH);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /auth/i);
    });

    it('invalid auth type throws', async () => {
      mockYaml(YAML_INVALID_AUTH_TYPE);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /invalid auth\.type/i);
    });

    it('duplicate domain throws', async () => {
      mockYaml(YAML_DUPLICATE_DOMAIN);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /api\.github\.com/);
    });

    it('agent references unknown service throws', async () => {
      mockYaml(YAML_UNKNOWN_AGENT_SERVICE);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /nonexistent/);
    });

    it('json_paths must start with $', async () => {
      mockYaml(YAML_INVALID_JSON_PATH);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /must start with "\$"/);
    });

    it('streaming_window_cap negative throws', async () => {
      mockYaml(YAML_INVALID_STREAMING_CAP);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /positive integer/);
    });

    it('streaming_window_cap float throws', async () => {
      mockYaml(YAML_STREAMING_CAP_FLOAT);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /positive integer/);
    });

    it('base_url ftp:// throws', async () => {
      mockYaml(YAML_INVALID_BASE_URL);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /http:\/\/|https:\/\//);
    });

    it('query_param requires param_name', async () => {
      mockYaml(YAML_QUERY_PARAM_MISSING_NAME);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /param_name/);
    });

    it('custom_header requires header_name', async () => {
      mockYaml(YAML_CUSTOM_HEADER_MISSING_NAME);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /header_name/);
    });

    it('sdk_env only {{placeholder}} supported', async () => {
      mockYaml(YAML_INVALID_SDK_ENV_TEMPLATE);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /\{\{placeholder\}\}/);
    });

    it('invalid heuristic config throws', async () => {
      mockYaml(YAML_INVALID_HEURISTIC_CONFIG);
      await assert.rejects(loadConfig('/fake/keyhole.yaml'), /min_length/i);
    });
  });

  describe('empty services block', () => {
    it('services: with all commented entries loads as empty config', async () => {
      mockYaml(YAML_EMPTY_SERVICES);
      const config = await loadConfig('/fake/keyhole.yaml');
      assert.deepEqual(Object.keys(config.services), []);
      assert.equal(config._domainToService.size, 0);
      assert.deepEqual(config._secretRefs, []);
    });
  });

  describe('auto-derived protocol', () => {
    it('localhost gets http://', async () => {
      mockYaml(YAML_LOCALHOST_AUTO_HTTP);
      const config = await loadConfig('/fake/keyhole.yaml');
      assert.equal(config.services.local.base_url, 'http://localhost:3000');
    });

    it('remote domain gets https://', async () => {
      mockYaml(YAML_REMOTE_AUTO_HTTPS);
      const config = await loadConfig('/fake/keyhole.yaml');
      assert.equal(config.services.github.base_url, 'https://api.github.com');
    });
  });

  describe('valid heuristic config', () => {
    it('parses heuristic config with all fields', async () => {
      mockYaml(YAML_HEURISTIC_CONFIG);
      const config = await loadConfig('/fake/keyhole.yaml');
      const h = config.services.github.response_masking?.heuristic;
      assert.equal(h?.enabled, true);
      assert.equal(h?.min_length, 20);
      assert.equal(h?.min_entropy, 4.0);
      assert.deepEqual(h?.additional_key_names, ['x_custom_token', 'my_secret_key']);
    });
  });

  describe('multi-service config', () => {
    it('YAML_MULTI_SERVICE: both services parsed with correct domains and secrets', async () => {
      mockYaml(YAML_MULTI_SERVICE);
      const config = await loadConfig('/fake/keyhole.yaml');
      assert.ok(config.services.github);
      assert.ok(config.services.openai);
      assert.equal(config._domainToService.get('api.github.com'), 'github');
      assert.equal(config._domainToService.get('api.openai.com'), 'openai');
      assert.ok(config._secretRefs.includes('github-token'));
      assert.ok(config._secretRefs.includes('openai-key'));
    });
  });

  describe('agents config', () => {
    it('YAML_WITH_AGENTS: agent-to-service mappings parsed correctly', async () => {
      mockYaml(YAML_WITH_AGENTS);
      const config = await loadConfig('/fake/keyhole.yaml');
      assert.ok(config.agents);
      assert.deepEqual(config.agents!['bot1'].services, ['github']);
      assert.deepEqual(config.agents!['bot2'].services, ['github', 'openai']);
      assert.equal(config._domainToService.get('api.github.com'), 'github');
      assert.equal(config._domainToService.get('api.openai.com'), 'openai');
      assert.ok(config._secretRefs.includes('github-token'));
      assert.ok(config._secretRefs.includes('openai-key'));
    });
  });

  describe('warnings', () => {
    it('unbounded pattern in streaming mode triggers console.warn', async () => {
      const warnMock = mock.method(console, 'warn', () => {});
      mockYaml(YAML_UNBOUNDED_PATTERN);
      await loadConfig('/fake/keyhole.yaml');
      assert.ok(warnMock.mock.calls.length > 0, 'Expected console.warn to be called');
      const msg = warnMock.mock.calls[0].arguments[0] as string;
      assert.ok(msg.includes('unbounded'), `Expected warning about unbounded pattern, got: ${msg}`);
      warnMock.mock.restore();
    });
  });
});
