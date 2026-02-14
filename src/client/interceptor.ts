import http from 'http';
import https from 'https';
import crypto from 'crypto';
import { IPCClient } from './ipc-client.js';
import { FakeClientRequest } from './fake-request.js';
import { isBodyBinary } from './binary-detect.js';
import type { ParsedConfig, DomainWithPrefix } from '../config/schema.js';

/**
 * Strip port from a host string, handling IPv6 bracket notation.
 * Examples: "localhost:8080" → "localhost", "[::1]:8080" → "::1", "[::1]" → "::1"
 */
function stripPort(host: string): string {
  if (host.startsWith('[')) {
    const closeBracket = host.indexOf(']');
    if (closeBracket !== -1) {
      return host.substring(1, closeBracket);
    }
    return host.substring(1);
  }
  const lastColon = host.lastIndexOf(':');
  if (lastColon === -1) return host;
  const afterColon = host.substring(lastColon + 1);
  if (/^\d+$/.test(afterColon)) {
    return host.substring(0, lastColon);
  }
  return host;
}

export class Interceptor {
  private ipc: IPCClient;
  private config: ParsedConfig;

  // Simple domain → service lookup
  private domainMap: Map<string, string>;
  // Path-prefix domain → service lookup (for shared domains)
  private prefixMap: Map<
    string,
    Array<{ prefix: string; service: string }>
  >;

  private originals: {
    httpsRequest: typeof https.request;
    httpsGet: typeof https.get;
    httpRequest: typeof http.request;
    httpGet: typeof http.get;
    fetch: typeof globalThis.fetch;
  };

  private installed = false;

  constructor(ipc: IPCClient, config: ParsedConfig) {
    this.ipc = ipc;
    this.config = config;

    this.domainMap = new Map();
    this.prefixMap = new Map();

    for (const [name, service] of Object.entries(config.services)) {
      for (const domain of service.domains) {
        if (typeof domain === 'string') {
          this.domainMap.set(domain, name);
        } else {
          const d = domain as DomainWithPrefix;
          const existing = this.prefixMap.get(d.host) || [];
          existing.push({ prefix: d.path_prefix, service: name });
          // Sort longest prefix first for correct matching
          existing.sort((a, b) => b.prefix.length - a.prefix.length);
          this.prefixMap.set(d.host, existing);
        }
      }
    }

    this.originals = {
      httpsRequest: https.request,
      httpsGet: https.get,
      httpRequest: http.request,
      httpGet: http.get,
      fetch: globalThis.fetch
    };
  }

  install(): void {
    if (this.installed) return;
    this.patchHttpModule(https, 'httpsRequest', 'httpsGet');
    this.patchHttpModule(http, 'httpRequest', 'httpGet');
    this.patchFetch();
    this.installed = true;
  }

  uninstall(): void {
    if (!this.installed) return;
    https.request = this.originals.httpsRequest;
    https.get = this.originals.httpsGet;
    http.request = this.originals.httpRequest;
    http.get = this.originals.httpGet;
    globalThis.fetch = this.originals.fetch;
    this.installed = false;
  }

  private resolveService(
    hostname: string,
    pathname: string
  ): string | null {
    const simple = this.domainMap.get(hostname);
    if (simple) return simple;

    const prefixed = this.prefixMap.get(hostname);
    if (prefixed) {
      for (const { prefix, service } of prefixed) {
        if (pathname.startsWith(prefix)) return service;
      }
    }

    return null;
  }

  private patchFetch(): void {
    const self = this;
    const originalFetch = this.originals.fetch;

    globalThis.fetch = async function (
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as Request).url;

      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return originalFetch.call(globalThis, input, init);
      }

      const service = self.resolveService(parsed.hostname, parsed.pathname);

      if (!service) {
        return originalFetch.call(globalThis, input, init);
      }

      return self.routeFetchThroughSidecar(parsed, init, service);
    };
  }

  private async routeFetchThroughSidecar(
    parsed: URL,
    init: RequestInit | undefined,
    service: string
  ): Promise<Response> {
    const id = crypto.randomUUID();

    let body: string | undefined;
    let bodyBase64: string | undefined;
    let bodyEncoding: 'utf8' | 'base64' = 'utf8';

    if (init?.body) {
      const rawBody =
        typeof init.body === 'string'
          ? Buffer.from(init.body)
          : Buffer.isBuffer(init.body)
            ? init.body
            : Buffer.from(init.body as ArrayBuffer);

      // Enforce body size limit client-side
      if (rawBody.length > 10 * 1024 * 1024) {
        throw new Error('Request body exceeds Keyhole limit (10MB).');
      }

      const contentType =
        new Headers(init?.headers).get('content-type') || undefined;

      if (isBodyBinary(contentType, rawBody)) {
        bodyBase64 = rawBody.toString('base64');
        bodyEncoding = 'base64';
      } else {
        body = rawBody.toString('utf-8');
        bodyEncoding = 'utf8';
      }
    }

    const response = await this.ipc.send({
      id,
      service,
      method: init?.method || 'GET',
      path: parsed.pathname + parsed.search,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body,
      bodyBase64,
      bodyEncoding
    });

    if (response.bodyEncoding === 'base64' && response.bodyBase64) {
      return new Response(Buffer.from(response.bodyBase64, 'base64'), {
        status: response.status,
        headers: response.headers
      });
    }

    return new Response(response.body, {
      status: response.status,
      headers: response.headers
    });
  }

  private patchHttpModule(
    mod: typeof http | typeof https,
    requestKey: 'httpRequest' | 'httpsRequest',
    getKey: 'httpGet' | 'httpsGet'
  ): void {
    const self = this;
    const originalRequest = this.originals[requestKey] as typeof http.request;
    const originalGet = this.originals[getKey] as typeof http.get;

    // Patch request
    (mod as any).request = function (
      ...args: any[]
    ): http.ClientRequest {
      const { hostname, pathname, service } =
        self.extractRequestInfo(args);

      if (!service) {
        return originalRequest.apply(mod, args as any);
      }

      // Extract callback from args. This follows the standard Node.js idiom
      // for monkey-patching http.request: the callback, when present, is always
      // the last argument per the Node.js API contract (the signature is
      // http.request(url[, options][, callback])). This convention is relied
      // upon by all known HTTP client libraries and is the established pattern
      // used in existing monkey-patching solutions (e.g., nock, mitm).
      const callback =
        typeof args[args.length - 1] === 'function'
          ? (args.pop() as (res: http.IncomingMessage) => void)
          : undefined;

      const { method, path: reqPath, headers } =
        self.extractRequestDetails(args, pathname);

      return new FakeClientRequest(
        self.ipc,
        service,
        method,
        reqPath,
        headers,
        callback
      ) as any;
    };

    // Patch get (same as request but calls .end() automatically)
    (mod as any).get = function (...args: any[]): http.ClientRequest {
      const req = (mod as any).request(...args);
      req.end();
      return req;
    };
  }

  private extractRequestInfo(args: any[]): {
    hostname: string;
    pathname: string;
    service: string | null;
  } {
    let hostname = '';
    let pathname = '/';

    if (typeof args[0] === 'string') {
      try {
        const url = new URL(args[0]);
        hostname = url.hostname;
        pathname = url.pathname;
      } catch {
        // not a URL
      }
    } else if (args[0] instanceof URL) {
      hostname = args[0].hostname;
      pathname = args[0].pathname;
    } else if (typeof args[0] === 'object' && args[0] !== null) {
      hostname = args[0].hostname || args[0].host || '';
      pathname = args[0].path || '/';
      // Strip port from host, handling IPv6 bracket notation (e.g. [::1]:8080)
      hostname = stripPort(hostname);
    }

    const service = hostname
      ? this.resolveService(hostname, pathname)
      : null;

    return { hostname, pathname, service };
  }

  private extractRequestDetails(
    args: any[],
    fallbackPath: string
  ): {
    method: string;
    path: string;
    headers: Record<string, string>;
  } {
    let method = 'GET';
    let reqPath = fallbackPath;
    let headers: Record<string, string> = {};

    if (typeof args[0] === 'string') {
      try {
        const url = new URL(args[0]);
        reqPath = url.pathname + url.search;
      } catch {
        // ignore
      }
      if (typeof args[1] === 'object' && args[1] !== null) {
        method = args[1].method || 'GET';
        headers = this.flattenHeaders(args[1].headers);
      }
    } else if (args[0] instanceof URL) {
      reqPath = args[0].pathname + args[0].search;
      if (typeof args[1] === 'object' && args[1] !== null) {
        method = args[1].method || 'GET';
        headers = this.flattenHeaders(args[1].headers);
      }
    } else if (typeof args[0] === 'object' && args[0] !== null) {
      method = args[0].method || 'GET';
      reqPath = args[0].path || fallbackPath;
      headers = this.flattenHeaders(args[0].headers);
    }

    return { method, path: reqPath, headers };
  }

  private flattenHeaders(
    headers: any
  ): Record<string, string> {
    if (!headers) return {};
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (value !== undefined && value !== null) {
        result[key.toLowerCase()] = String(value);
      }
    }
    return result;
  }
}
