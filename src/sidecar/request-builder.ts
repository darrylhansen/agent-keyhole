import type { ParsedConfig, ServiceConfig, AuthConfig } from '../config/schema.js';
import type { KeyholeRequest } from './ipc-types.js';

export class RequestBuilder {
  private config: ParsedConfig;
  private secrets: Map<string, string>;

  constructor(config: ParsedConfig, secrets: Map<string, string>) {
    this.config = config;
    this.secrets = secrets;
  }

  build(request: KeyholeRequest): { url: string; options: RequestInit } {
    const service = this.config.services[request.service];
    if (!service) throw new Error(`Unknown service: ${request.service}`);

    let url = service.base_url!.replace(/\/$/, '') + request.path;

    const secret = this.secrets.get(service.auth.secret_ref);
    if (!secret) {
      throw new Error(`Secret not resolved for: ${service.auth.secret_ref}`);
    }

    const headers: Record<string, string> = {};

    switch (service.auth.type) {
      case 'bearer':
        headers['Authorization'] = `Bearer ${secret}`;
        break;
      case 'basic': {
        const basicAuth = service.auth as AuthConfig & { type: 'basic' };
        if (basicAuth.username) {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${basicAuth.username}:${secret}`
          ).toString('base64')}`;
        } else {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${secret}:`
          ).toString('base64')}`;
        }
        break;
      }
      case 'query_param': {
        const qpAuth = service.auth as AuthConfig & { type: 'query_param' };
        const urlObj = new URL(url);
        urlObj.searchParams.set(qpAuth.param_name, secret);
        url = urlObj.toString();
        break;
      }
      case 'custom_header': {
        const chAuth = service.auth as AuthConfig & { type: 'custom_header' };
        headers[chAuth.header_name] = secret;
        break;
      }
    }

    // Add service-specific headers from config
    if (service.headers) Object.assign(headers, service.headers);
    headers['User-Agent'] = 'agent-keyhole/1.0';

    // Whitelist: only forward Content-Type and Accept from agent
    if (request.headers['content-type']) {
      headers['Content-Type'] = request.headers['content-type'];
    }
    if (request.headers['accept'] && !headers['Accept']) {
      headers['Accept'] = request.headers['accept'];
    }

    // Decode binary body from Base64 back to raw bytes for upstream
    let body: string | Buffer | undefined;
    if (request.bodyEncoding === 'base64' && request.bodyBase64) {
      body = Buffer.from(request.bodyBase64, 'base64');
    } else {
      body = request.body || undefined;
    }

    return {
      url,
      options: {
        method: request.method,
        headers,
        body: body as any
      }
    };
  }

  /**
   * Build auth headers for a specific service. Used by redirect handler to
   * re-inject credentials when a redirect chain returns to a trusted domain.
   */
  buildAuthHeaders(serviceName: string): Record<string, string> {
    const service = this.config.services[serviceName];
    if (!service) return {};

    const secret = this.secrets.get(service.auth.secret_ref);
    if (!secret) return {};

    const headers: Record<string, string> = {};

    switch (service.auth.type) {
      case 'bearer':
        headers['Authorization'] = `Bearer ${secret}`;
        break;
      case 'basic': {
        const basicAuth = service.auth as AuthConfig & { type: 'basic' };
        if (basicAuth.username) {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${basicAuth.username}:${secret}`
          ).toString('base64')}`;
        } else {
          headers['Authorization'] = `Basic ${Buffer.from(
            `${secret}:`
          ).toString('base64')}`;
        }
        break;
      }
      case 'custom_header': {
        const chAuth = service.auth as AuthConfig & { type: 'custom_header' };
        headers[chAuth.header_name] = secret;
        break;
      }
      // query_param is handled via URL, not headers
    }

    return headers;
  }

  /**
   * Re-inject query_param auth into a URL. Used by redirect handler when
   * a redirect chain returns to a trusted domain.
   */
  injectQueryParamAuth(url: URL, serviceName: string): void {
    const service = this.config.services[serviceName];
    if (!service || service.auth.type !== 'query_param') return;

    const qpAuth = service.auth as AuthConfig & { type: 'query_param' };
    const secret = this.secrets.get(service.auth.secret_ref);
    if (!secret) return;

    url.searchParams.set(qpAuth.param_name, secret);
  }

  getInjectedSecrets(): string[] {
    return Array.from(this.secrets.values());
  }

  getSecrets(): Map<string, string> {
    return this.secrets;
  }

  getServiceConfig(name: string): ServiceConfig {
    return this.config.services[name];
  }
}
