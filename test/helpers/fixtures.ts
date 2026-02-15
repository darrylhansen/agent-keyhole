/**
 * Shared test fixtures — constants, factories, and pre-built configs.
 * No I/O, no mocking. Pure data.
 */

import crypto from 'crypto';
import type {
  ParsedConfig,
  ServiceConfig,
  AuthConfig,
  DomainWithPrefix,
  HeuristicConfig,
  ResponseMaskingConfig,
} from '../../src/config/schema.js';

// ────────────────── Test Secrets ──────────────────

/** 40-char GitHub-like PAT (well above MIN_SECRET_LENGTH=8) */
export const TEST_SECRET = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';
export const TEST_SECRET_B64 = Buffer.from(TEST_SECRET).toString('base64');
export const TEST_SECRET_URL = encodeURIComponent(TEST_SECRET);

/** Second secret for multi-service tests */
export const OPENAI_SECRET = 'sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK';
export const OPENAI_SECRET_B64 = Buffer.from(OPENAI_SECRET).toString('base64');

/** Secret with URL-special characters (+, =, /) that change under encodeURIComponent */
export const SECRET_WITH_SPECIAL_CHARS = 'sk+test/key=abc123def456ghi789jkl012';
export const SECRET_WITH_SPECIAL_CHARS_URL = encodeURIComponent(SECRET_WITH_SPECIAL_CHARS);

/** 7 chars — below MIN_SECRET_LENGTH=8, should be excluded */
export const SHORT_SECRET = 'abc1234';

/** Placeholder value — should never be treated as a secret */
export const PLACEHOLDER = 'KEYHOLE_MANAGED';

/** Custom placeholder for override testing */
export const CUSTOM_PLACEHOLDER = 'REDACTED_BY_TESTS';

// ────────────────── Entropy Test Values ──────────────────

/** 64-char hex string from random bytes — well above 3.5 Shannon entropy threshold */
export const HIGH_ENTROPY_VALUE = crypto.randomBytes(32).toString('hex');

/** 21 repeated chars — near-zero entropy (satisfies >16 length check but low entropy) */
export const LOW_ENTROPY_VALUE = 'aaaaaaaaaaaaaaaaaaaaa';

/** JWT-like token for heuristic testing — looks like a real OAuth token */
export const JWT_LIKE_TOKEN =
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik' +
  'pvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoT' +
  'yoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85';

// ────────────────── Exclusion Pattern Test Values ──────────────────

export const TEST_UUID = '550e8400-e29b-41d4-a716-446655440000';
export const TEST_OBJECT_ID = '507f1f77bcf86cd799439011';
export const TEST_URL = 'https://api.example.com/v1/resource?page=1';
export const TEST_TIMESTAMP = '2024-01-15T10:30:00.000Z';
export const TEST_EMAIL = 'user@example.com';

// ────────────────── Config Factories ──────────────────

/**
 * Build a valid ParsedConfig with internal _domainToService Map.
 * Override any property via the services/agents params.
 */
export function makeConfig(
  services: Record<string, ServiceConfig>,
  agents?: Record<string, { services: string[] }>
): ParsedConfig {
  const domainToService = new Map<string, string>();
  const secretRefs: string[] = [];

  for (const [name, svc] of Object.entries(services)) {
    for (const d of svc.domains) {
      const host = typeof d === 'string' ? d : d.host;
      domainToService.set(host, name);
    }
    if (!secretRefs.includes(svc.auth.secret_ref)) {
      secretRefs.push(svc.auth.secret_ref);
    }
  }

  return {
    services,
    agents,
    _domainToService: domainToService,
    _secretRefs: secretRefs,
  };
}

/** Build a Map<string, string> of secret_ref → secret value */
export function makeSecretsMap(
  overrides?: Record<string, string>
): Map<string, string> {
  const base: Record<string, string> = {
    'github-token': TEST_SECRET,
    'openai-key': OPENAI_SECRET,
    ...overrides,
  };
  return new Map(Object.entries(base));
}

// ────────────────── Pre-built Configs ──────────────────

/** Single service with bearer auth */
export const SINGLE_BEARER_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
  },
});

/** Multi-service config */
export const MULTI_SERVICE_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
  },
  openai: {
    domains: ['api.openai.com'],
    auth: { type: 'bearer', secret_ref: 'openai-key' } as AuthConfig,
    base_url: 'https://api.openai.com',
  },
});

/** Query param auth */
export const QUERY_PARAM_CONFIG = makeConfig({
  maps: {
    domains: ['maps.googleapis.com'],
    auth: {
      type: 'query_param',
      param_name: 'key',
      secret_ref: 'maps-key',
    } as AuthConfig,
    base_url: 'https://maps.googleapis.com',
  },
});

/** Basic auth with username */
export const BASIC_AUTH_CONFIG = makeConfig({
  jira: {
    domains: ['mycompany.atlassian.net'],
    auth: {
      type: 'basic',
      secret_ref: 'jira-token',
      username: 'user@example.com',
    } as AuthConfig,
    base_url: 'https://mycompany.atlassian.net',
  },
});

/** Basic auth without username */
export const BASIC_AUTH_NO_USER_CONFIG = makeConfig({
  service: {
    domains: ['api.example.com'],
    auth: {
      type: 'basic',
      secret_ref: 'example-token',
    } as AuthConfig,
    base_url: 'https://api.example.com',
  },
});

/** Custom header auth */
export const CUSTOM_HEADER_CONFIG = makeConfig({
  custom: {
    domains: ['custom.api.com'],
    auth: {
      type: 'custom_header',
      header_name: 'X-Custom-Key',
      secret_ref: 'custom-key',
    } as AuthConfig,
    base_url: 'https://custom.api.com',
  },
});

/** Config with sdk_env for safe-env testing */
export const WITH_SDK_ENV_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
    sdk_env: { GITHUB_TOKEN: '{{placeholder}}' },
  },
  openai: {
    domains: ['api.openai.com'],
    auth: { type: 'bearer', secret_ref: 'openai-key' } as AuthConfig,
    base_url: 'https://api.openai.com',
    sdk_env: { OPENAI_API_KEY: '{{placeholder}}' },
    placeholder: CUSTOM_PLACEHOLDER,
  },
});

/** Config with heuristic detection enabled */
export const WITH_HEURISTIC_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
    response_masking: {
      heuristic: { enabled: true },
    },
  },
});

/** Config with heuristic disabled */
export const HEURISTIC_DISABLED_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
    response_masking: {
      heuristic: { enabled: false },
    },
  },
});

/** Config with L4 patterns and json_paths */
export const WITH_L4_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
    response_masking: {
      patterns: ['ghp_[a-zA-Z0-9]{36}'],
      json_paths: ['$.credentials.access_token'],
    },
  },
});

/** Config with agents (multi-agent AC) */
export const WITH_AGENTS_CONFIG = makeConfig(
  {
    github: {
      domains: ['api.github.com'],
      auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
      base_url: 'https://api.github.com',
    },
    openai: {
      domains: ['api.openai.com'],
      auth: { type: 'bearer', secret_ref: 'openai-key' } as AuthConfig,
      base_url: 'https://api.openai.com',
    },
  },
  {
    'content-bot': { services: ['github'] },
    'coding-bot': { services: ['github', 'openai'] },
  }
);

/** Two services on the same domain with different path prefixes */
export const PATH_PREFIX_CONFIG = makeConfig({
  'svc-a': {
    domains: [{ host: 'api.shared.com', path_prefix: '/v1' } as DomainWithPrefix],
    auth: { type: 'bearer', secret_ref: 'svc-a-token' } as AuthConfig,
    base_url: 'https://api.shared.com',
  },
  'svc-b': {
    domains: [{ host: 'api.shared.com', path_prefix: '/v2' } as DomainWithPrefix],
    auth: { type: 'bearer', secret_ref: 'svc-b-token' } as AuthConfig,
    base_url: 'https://api.shared.com',
  },
});

/** Local service (http://) */
export const LOCAL_SERVICE_CONFIG = makeConfig({
  local: {
    domains: ['localhost:3000'],
    auth: { type: 'bearer', secret_ref: 'local-token' } as AuthConfig,
    base_url: 'http://localhost:3000',
  },
});

/** Config with streaming window cap */
export const STREAMING_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
    response_masking: {
      streaming: 'stream',
      streaming_window_cap: 100,
      heuristic: { enabled: true },
      json_paths: ['$.credentials.token'],
    },
  },
});

/** Config with service-specific headers */
export const WITH_HEADERS_CONFIG = makeConfig({
  github: {
    domains: ['api.github.com'],
    auth: { type: 'bearer', secret_ref: 'github-token' } as AuthConfig,
    base_url: 'https://api.github.com',
    headers: {
      'X-GitHub-Api-Version': '2022-11-28',
      Accept: 'application/vnd.github+json',
    },
  },
});

// ────────────────── Test Response Bodies ──────────────────

/** JSON response containing a known secret */
export const JSON_WITH_SECRET = JSON.stringify({
  user: 'octocat',
  token: TEST_SECRET,
  id: 12345,
});

/** JSON response with secret as substring in URL */
export const JSON_WITH_SECRET_IN_URL = JSON.stringify({
  clone_url: `https://api.github.com/repos/user/repo?key=${TEST_SECRET}`,
});

/** JSON response with heuristic-triggering fields */
export const JSON_WITH_HEURISTIC = JSON.stringify({
  access_token: HIGH_ENTROPY_VALUE,
  token_type: 'bearer',
  session_id: TEST_UUID,
  expires_in: 3600,
});

/** JSON response with nested structure for json_path testing */
export const JSON_WITH_NESTED = JSON.stringify({
  credentials: {
    access_token: 'some-secret-value-that-should-be-redacted',
  },
  data: [
    { name: 'a', secret: 'hidden-value-one' },
    { name: 'b', secret: 'hidden-value-two' },
  ],
});

/** Plain text containing a secret */
export const PLAIN_TEXT_WITH_SECRET = `Your API key is: ${TEST_SECRET}\nPlease keep it safe.`;

/** HTML containing a secret */
export const HTML_WITH_SECRET = `<html><body><p>Token: ${TEST_SECRET}</p></body></html>`;

// ────────────────── YAML Config Strings (for config-loader tests) ──────────────────

export const VALID_YAML = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    sdk_env:
      GITHUB_TOKEN: "{{placeholder}}"
    response_masking:
      patterns:
        - "ghp_[a-zA-Z0-9]{36}"
      json_paths:
        - "$.token"
`;

export const YAML_MISSING_SERVICES = `
logging:
  level: info
`;

export const YAML_MISSING_DOMAINS = `
services:
  github:
    auth:
      type: bearer
      secret_ref: github-token
`;

export const YAML_MISSING_AUTH = `
services:
  github:
    domains:
      - api.github.com
`;

export const YAML_INVALID_AUTH_TYPE = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: oauth
      secret_ref: github-token
`;

export const YAML_DUPLICATE_DOMAIN = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
  github2:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token-2
`;

export const YAML_UNKNOWN_AGENT_SERVICE = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
agents:
  bot1:
    services:
      - github
      - nonexistent
`;

export const YAML_INVALID_JSON_PATH = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    response_masking:
      json_paths:
        - "token"
`;

export const YAML_INVALID_STREAMING_CAP = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    response_masking:
      streaming_window_cap: -1
`;

export const YAML_INVALID_BASE_URL = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    base_url: "ftp://api.github.com"
`;

export const YAML_LOCALHOST_AUTO_HTTP = `
services:
  local:
    domains:
      - localhost:3000
    auth:
      type: bearer
      secret_ref: local-token
`;

export const YAML_REMOTE_AUTO_HTTPS = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
`;

export const YAML_INVALID_SDK_ENV_TEMPLATE = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    sdk_env:
      GITHUB_TOKEN: "{{secret}}"
`;

export const YAML_QUERY_PARAM_MISSING_NAME = `
services:
  maps:
    domains:
      - maps.googleapis.com
    auth:
      type: query_param
      secret_ref: maps-key
`;

export const YAML_CUSTOM_HEADER_MISSING_NAME = `
services:
  custom:
    domains:
      - custom.api.com
    auth:
      type: custom_header
      secret_ref: custom-key
`;

export const YAML_WITH_AGENTS = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
  openai:
    domains:
      - api.openai.com
    auth:
      type: bearer
      secret_ref: openai-key
agents:
  bot1:
    services:
      - github
  bot2:
    services:
      - github
      - openai
`;

export const YAML_MULTI_SERVICE = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    sdk_env:
      GITHUB_TOKEN: "{{placeholder}}"
  openai:
    domains:
      - api.openai.com
    auth:
      type: bearer
      secret_ref: openai-key
    sdk_env:
      OPENAI_API_KEY: "{{placeholder}}"
    placeholder: "${CUSTOM_PLACEHOLDER}"
`;

/** Unbounded pattern in streaming mode — triggers console.warn */
export const YAML_UNBOUNDED_PATTERN = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    response_masking:
      streaming: stream
      patterns:
        - "ghp_[a-zA-Z0-9]+"
`;

/** Valid heuristic config with all fields */
export const YAML_HEURISTIC_CONFIG = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    response_masking:
      heuristic:
        enabled: true
        min_length: 20
        min_entropy: 4.0
        additional_key_names:
          - x_custom_token
          - my_secret_key
`;

/** Invalid heuristic config — min_length is negative */
export const YAML_INVALID_HEURISTIC_CONFIG = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    response_masking:
      heuristic:
        min_length: -1
`;

/** Invalid streaming_window_cap — float instead of integer */
export const YAML_STREAMING_CAP_FLOAT = `
services:
  github:
    domains:
      - api.github.com
    auth:
      type: bearer
      secret_ref: github-token
    response_masking:
      streaming_window_cap: 3.5
`;

// ────────────────── Redaction Marker ──────────────────

export const REDACTION_MARKER = '[REDACTED BY KEYHOLE]';
