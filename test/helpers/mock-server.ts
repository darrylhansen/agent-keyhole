/**
 * Lightweight HTTP mock server for integration tests.
 *
 * Each test creates its own server instance — no shared mutable state.
 * Listens on 127.0.0.1 with an OS-assigned random port.
 */

import http from 'http';

export interface Route {
  method?: string;              // default: 'GET'
  path: string;
  status?: number;              // default: 200
  headers?: Record<string, string>;
  body?: string | Buffer;
  delay?: number;               // ms delay before responding
  redirectTo?: string;          // sets Location header
  redirectStatus?: number;      // default: 302
  handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void;
}

export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  rawBody: Buffer;
}

export interface MockServer {
  /** Base URL: 'http://127.0.0.1:<port>' */
  url: string;
  /** Assigned port */
  port: number;
  /** Add a route dynamically after creation */
  addRoute(route: Route): void;
  /** Get all recorded requests for a given path */
  getRequests(path: string): RecordedRequest[];
  /** Get all recorded requests */
  getAllRequests(): RecordedRequest[];
  /** Reset recorded requests */
  clearRequests(): void;
  /** Shut down the server */
  close(): Promise<void>;
}

/**
 * Create a mock HTTP server with optional initial routes.
 * Resolves once listening.
 */
export async function createMockServer(routes?: Route[]): Promise<MockServer> {
  const routeMap = new Map<string, Route>();
  const requests: RecordedRequest[] = [];

  if (routes) {
    for (const route of routes) {
      const key = `${(route.method || 'GET').toUpperCase()} ${route.path}`;
      routeMap.set(key, route);
    }
  }

  const server = http.createServer(async (req, res) => {
    const method = req.method || 'GET';
    const urlPath = req.url || '/';

    // Record the request
    const bodyChunks: Buffer[] = [];
    for await (const chunk of req) {
      bodyChunks.push(chunk as Buffer);
    }
    const rawBody = Buffer.concat(bodyChunks);
    const bodyStr = rawBody.toString('utf8');

    requests.push({
      method,
      path: urlPath,
      headers: req.headers as Record<string, string | string[] | undefined>,
      body: bodyStr,
      rawBody,
    });

    // Match route: try exact "METHOD /path" first, then wildcard "* /path"
    const exactKey = `${method.toUpperCase()} ${urlPath}`;
    // Also try matching without query string
    const pathOnly = urlPath.split('?')[0];
    const exactKeyNoQuery = `${method.toUpperCase()} ${pathOnly}`;
    const wildcardKey = `* ${urlPath}`;
    const wildcardKeyNoQuery = `* ${pathOnly}`;

    const route =
      routeMap.get(exactKey) ||
      routeMap.get(exactKeyNoQuery) ||
      routeMap.get(wildcardKey) ||
      routeMap.get(wildcardKeyNoQuery);

    if (!route) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    // Custom handler overrides everything
    if (route.handler) {
      route.handler(req, res);
      return;
    }

    // Optional delay
    if (route.delay) {
      await new Promise((resolve) => setTimeout(resolve, route.delay));
    }

    // Redirect
    if (route.redirectTo) {
      const status = route.redirectStatus || 302;
      const headers: Record<string, string> = {
        Location: route.redirectTo,
        ...(route.headers || {}),
      };
      res.writeHead(status, headers);
      res.end(route.body || '');
      return;
    }

    // Normal response
    const status = route.status || 200;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(route.headers || {}),
    };

    res.writeHead(status, headers);
    res.end(route.body || '');
  });

  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Unexpected server address'));
        return;
      }

      const port = addr.port;
      const url = `http://127.0.0.1:${port}`;

      resolve({
        url,
        port,
        addRoute(route: Route) {
          const key = `${(route.method || 'GET').toUpperCase()} ${route.path}`;
          routeMap.set(key, route);
        },
        getRequests(path: string) {
          return requests.filter(
            (r) => r.path === path || r.path.split('?')[0] === path
          );
        },
        getAllRequests() {
          return [...requests];
        },
        clearRequests() {
          requests.length = 0;
        },
        close() {
          return new Promise<void>((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          });
        },
      });
    });

    server.on('error', reject);
  });
}
