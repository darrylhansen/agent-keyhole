import fs from 'fs';
import yaml from 'js-yaml';
import type {
  KeyholeConfig,
  ParsedConfig,
  ServiceConfig,
  AuthConfig
} from './schema.js';

/**
 * Strip port from a host string, handling IPv6 bracket notation.
 * Examples: "localhost:8080" → "localhost", "[::1]:8080" → "::1", "[::1]" → "::1"
 */
function stripPort(host: string): string {
  if (host.startsWith('[')) {
    // IPv6 bracket notation: [::1]:port or [::1]
    const closeBracket = host.indexOf(']');
    if (closeBracket !== -1) {
      return host.substring(1, closeBracket);
    }
    return host.substring(1); // malformed, best-effort
  }
  // IPv4 or hostname: only split on the last colon if it looks like a port
  const lastColon = host.lastIndexOf(':');
  if (lastColon === -1) return host;
  // If the part after the colon is all digits, treat it as a port
  const afterColon = host.substring(lastColon + 1);
  if (/^\d+$/.test(afterColon)) {
    return host.substring(0, lastColon);
  }
  return host;
}

/**
 * Determine if a hostname refers to a local/internal service.
 * Used to decide default protocol (http vs https) when base_url is not explicit.
 */
function isLocalHost(host: string): boolean {
  const hostname = stripPort(host);

  if (hostname === 'localhost') return true;
  if (hostname === '127.0.0.1') return true;
  if (hostname === '::1') return true;
  if (hostname === '0.0.0.0') return true;

  if (/^10\./.test(hostname)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;
  if (/^192\.168\./.test(hostname)) return true;

  return false;
}

export async function loadConfig(configPath: string): Promise<ParsedConfig> {
  const raw = fs.readFileSync(configPath, 'utf-8');
  const config = yaml.load(raw) as KeyholeConfig;
  validateConfig(config);

  const domainToService = new Map<string, string>();
  const secretRefs: string[] = [];

  for (const [name, service] of Object.entries(config.services)) {
    for (const domain of service.domains) {
      if (typeof domain === 'string') {
        if (domainToService.has(domain)) {
          throw new Error(
            `Domain "${domain}" mapped to both "${domainToService.get(domain)}" and "${name}"`
          );
        }
        domainToService.set(domain, name);
      }
    }

    // Derive base_url from first domain if not set explicitly
    if (!service.base_url) {
      const firstDomain = service.domains[0];
      const host =
        typeof firstDomain === 'string' ? firstDomain : firstDomain.host;
      const protocol = isLocalHost(host) ? 'http' : 'https';
      service.base_url = `${protocol}://${host}`;
    }

    secretRefs.push(service.auth.secret_ref);
  }

  return {
    ...config,
    _domainToService: domainToService,
    _secretRefs: [...new Set(secretRefs)]
  };
}

function validateConfig(config: KeyholeConfig): void {
  // 'services' key missing entirely — invalid config
  if (!('services' in config)) {
    throw new Error('keyhole.yaml must have a "services" section');
  }
  // services: with all examples commented out parses as null — valid after init
  if (config.services === null || config.services === undefined) {
    config.services = {};
    return;
  }
  if (typeof config.services !== 'object') {
    throw new Error('keyhole.yaml must have a "services" section');
  }

  for (const [name, service] of Object.entries(config.services)) {
    if (!service.domains?.length) {
      throw new Error(`Service "${name}" must have at least one domain`);
    }
    if (!service.auth?.type || !service.auth?.secret_ref) {
      throw new Error(
        `Service "${name}" must have auth.type and auth.secret_ref`
      );
    }

    const validAuthTypes = ['bearer', 'basic', 'query_param', 'custom_header'];
    if (!validAuthTypes.includes(service.auth.type)) {
      throw new Error(
        `Service "${name}" has invalid auth.type "${service.auth.type}"`
      );
    }

    if (
      service.auth.type === 'query_param' &&
      !(service.auth as AuthConfig & { type: 'query_param' }).param_name
    ) {
      throw new Error(
        `Service "${name}" with query_param auth requires param_name`
      );
    }
    if (
      service.auth.type === 'custom_header' &&
      !(service.auth as AuthConfig & { type: 'custom_header' }).header_name
    ) {
      throw new Error(
        `Service "${name}" with custom_header auth requires header_name`
      );
    }

    // Validate explicit base_url protocol
    if (service.base_url) {
      if (
        !service.base_url.startsWith('http://') &&
        !service.base_url.startsWith('https://')
      ) {
        throw new Error(
          `Service "${name}" has invalid base_url: "${service.base_url}" – ` +
            `must start with http:// or https://`
        );
      }
    }

    // Validate streaming_window_cap
    if (service.response_masking?.streaming_window_cap !== undefined) {
      const cap = service.response_masking.streaming_window_cap;
      if (typeof cap !== 'number' || cap < 1 || !Number.isInteger(cap)) {
        throw new Error(
          `Service "${name}" has invalid streaming_window_cap: must be a positive integer`
        );
      }
    }

    // Validate regex patterns
    if (service.response_masking?.patterns) {
      const streaming = service.response_masking.streaming || 'stream';
      const windowCap = service.response_masking.streaming_window_cap ?? 200;
      for (const pattern of service.response_masking.patterns) {
        try {
          new RegExp(pattern);
        } catch (e: any) {
          throw new Error(
            `Service "${name}" has invalid regex: "${pattern}" – ${e.message}`
          );
        }
        if (
          streaming === 'stream' &&
          /[+*]/.test(pattern) &&
          !/\{\d+\}/.test(pattern)
        ) {
          console.warn(
            `[keyhole] Warning: Service "${name}" has unbounded pattern "${pattern}" ` +
              `in streaming mode (window cap: ${windowCap}). Consider increasing ` +
              `streaming_window_cap, using "streaming: buffer", or bounded quantifiers.`
          );
        }
      }
    }

    // Validate json_paths syntax
    if (service.response_masking?.json_paths) {
      for (const jp of service.response_masking.json_paths) {
        if (!jp.startsWith('$')) {
          throw new Error(
            `Service "${name}" has invalid json_path: "${jp}" – must start with "$"`
          );
        }
      }
    }

    // Validate heuristic config
    if (service.response_masking?.heuristic) {
      const h = service.response_masking.heuristic;
      if (h.enabled !== undefined && typeof h.enabled !== 'boolean') {
        throw new Error(
          `Service "${name}" has invalid heuristic.enabled: must be boolean`
        );
      }
      if (h.min_length !== undefined) {
        if (typeof h.min_length !== 'number' || h.min_length < 1 || !Number.isInteger(h.min_length)) {
          throw new Error(
            `Service "${name}" has invalid heuristic.min_length: must be a positive integer`
          );
        }
      }
      if (h.min_entropy !== undefined) {
        if (typeof h.min_entropy !== 'number' || h.min_entropy <= 0) {
          throw new Error(
            `Service "${name}" has invalid heuristic.min_entropy: must be a positive number`
          );
        }
      }
      if (h.additional_key_names !== undefined) {
        if (
          !Array.isArray(h.additional_key_names) ||
          !h.additional_key_names.every((k: any) => typeof k === 'string')
        ) {
          throw new Error(
            `Service "${name}" has invalid heuristic.additional_key_names: must be string array`
          );
        }
      }
    }

    if (service.sdk_env) {
      for (const [envVar, template] of Object.entries(service.sdk_env)) {
        if (template.includes('{{') && !template.includes('{{placeholder}}')) {
          throw new Error(
            `Service "${name}" sdk_env.${envVar}: only {{placeholder}} supported`
          );
        }
      }
    }
  }

  if (config.agents) {
    const serviceNames = new Set(Object.keys(config.services));
    for (const [agentName, agent] of Object.entries(config.agents)) {
      for (const svc of agent.services) {
        if (!serviceNames.has(svc)) {
          throw new Error(
            `Agent "${agentName}" references unknown service "${svc}"`
          );
        }
      }
    }
  }
}
