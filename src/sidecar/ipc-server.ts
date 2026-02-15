import net from 'net';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import type { KeyholeRequest, KeyholeResponse } from './ipc-types.js';
import type { RequestBuilder } from './request-builder.js';
import type { ResponseMasker } from './response-masker.js';
import type { AuditLogger } from './audit-logger.js';
import { sanitizePathForLog } from './audit-logger.js';
import type { ParsedConfig } from '../config/schema.js';

/** Maximum IPC message size: 10MB body + 64KB overhead for headers/metadata */
const MAX_IPC_MESSAGE_SIZE = 10 * 1024 * 1024 + 64 * 1024;

/** Maximum redirect hops */
const MAX_REDIRECTS = 10;

let _server: net.Server | null = null;
let _builder: RequestBuilder | null = null;
let _masker: ResponseMasker | null = null;

export function updateServerHandlers(
  builder: RequestBuilder,
  masker: ResponseMasker
): void {
  _builder = builder;
  _masker = masker;
}

export async function startIPCServer(
  ott: string,
  builder: RequestBuilder | null,
  masker: ResponseMasker | null,
  logger: AuditLogger,
  socketDir?: string,
  agentServices?: Map<string, string[]>
): Promise<string> {
  _builder = builder;
  _masker = masker;

  const socketId = crypto.randomBytes(16).toString('hex');
  const dir = socketDir || os.tmpdir();
  const socketPath = path.join(dir, `keyhole-${socketId}.sock`);

  const server = net.createServer((conn) => {
    let chunks: Buffer[] = [];
    let totalLength = 0;

    // Prevent unhandled 'error' events (e.g. ECONNRESET, EPIPE) from
    // crashing the sidecar process. Individual socket failures are
    // expected during client disconnects and sidecar restarts.
    conn.on('error', (err: Error) => {
      logger.warn('ipc.connection_error', { error: err.message });
    });

    conn.on('data', (data: Buffer) => {
      chunks.push(data);
      totalLength += data.length;

      while (totalLength >= 4) {
        const headerBuf =
          chunks.length === 1
            ? chunks[0]
            : Buffer.concat(chunks);
        const payloadLength = headerBuf.readUInt32BE(0);

        if (payloadLength > MAX_IPC_MESSAGE_SIZE) {
          logger.warn('ipc.message_too_large', {
            error: `Rejected message: ${payloadLength} bytes`
          });
          conn.destroy();
          return;
        }

        if (totalLength < 4 + payloadLength) break;

        const fullBuffer =
          chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
        const payload = fullBuffer.subarray(4, 4 + payloadLength);

        const remaining = fullBuffer.subarray(4 + payloadLength);
        chunks = remaining.length > 0 ? [remaining] : [];
        totalLength = remaining.length;

        try {
          const request = JSON.parse(
            payload.toString('utf-8')
          ) as KeyholeRequest;
          handleRequest(request, conn, ott, logger, agentServices);
        } catch (parseErr: any) {
          logger.warn('request.malformed', {
            error: `Malformed IPC JSON: ${parseErr.message}`
          });
          continue;
        }
      }
    });
  });

  _server = server;

  return new Promise((resolve, reject) => {
    // Clean up zombie socket files from previous hard exits
    if (fs.existsSync(socketPath)) {
      const testConn = net.createConnection(socketPath);
      testConn.on('connect', () => {
        testConn.destroy();
        reject(new Error(`Keyhole socket already in use: ${socketPath}`));
      });
      testConn.on('error', () => {
        try {
          fs.unlinkSync(socketPath);
        } catch {
          // ignore
        }
        listenOnSocket();
      });
    } else {
      listenOnSocket();
    }

    function listenOnSocket(): void {
      server.listen(socketPath, () => {
        fs.chmodSync(socketPath, 0o600);
        resolve(socketPath);
      });
      server.on('error', reject);
    }
  });
}

export async function stopIPCServer(socketPath?: string): Promise<void> {
  return new Promise((resolve) => {
    if (_server) {
      _server.close(() => {
        if (socketPath) {
          try {
            fs.unlinkSync(socketPath);
          } catch {
            // ignore
          }
        }
        _server = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

async function handleRequest(
  request: KeyholeRequest,
  conn: net.Socket,
  ott: string,
  logger: AuditLogger,
  agentServices?: Map<string, string[]>
): Promise<void> {
  // Health check (works even in PENDING_UNLOCK)
  if (request.service === '__health__') {
    const state = _builder ? 'ready' : 'pending_unlock';
    sendResponse(conn, {
      id: request.id,
      status: state === 'ready' ? 200 : 503,
      headers: {},
      body: JSON.stringify({ state, uptime: process.uptime() }),
      bodyEncoding: 'utf8',
      redacted: false
    });
    return;
  }

  // Validate OTT with timing-safe comparison
  if (request.ott.length !== ott.length ||
      !crypto.timingSafeEqual(Buffer.from(request.ott), Buffer.from(ott))) {
    sendResponse(conn, {
      id: request.id,
      status: 403,
      headers: {},
      body: '',
      bodyEncoding: 'utf8',
      error: 'Invalid authentication token'
    });
    logger.warn('request.rejected', { error: 'Invalid OTT' });
    return;
  }

  // Multi-agent access control
  if (agentServices && request.agent) {
    const allowed = agentServices.get(request.agent);
    if (allowed && !allowed.includes(request.service)) {
      sendResponse(conn, {
        id: request.id,
        status: 403,
        headers: {},
        body: '',
        bodyEncoding: 'utf8',
        error: `Agent "${request.agent}" not authorized for service "${request.service}"`
      });
      logger.warn('request.rejected', {
        agent: request.agent,
        service: request.service,
        error: 'Agent not authorized for service'
      });
      return;
    }
  }

  // Check if sidecar is ready (vault might be locked)
  if (!_builder || !_masker) {
    sendResponse(conn, {
      id: request.id,
      status: 503,
      headers: {},
      body: '',
      bodyEncoding: 'utf8',
      error: 'Vault is locked – passphrase required'
    });
    return;
  }

  const startTime = Date.now();

  try {
    const { url, options } = _builder.build(request);
    const service = _builder.getServiceConfig(request.service);

    const upstreamResponse = await fetchWithRedirectPolicy(
      url,
      options,
      request.service,
      _builder
    );

    const contentType = upstreamResponse.headers.get('content-type') || '';
    const rawBuffer = Buffer.from(await upstreamResponse.arrayBuffer());
    const isBinary = _masker.isBinaryResponse(contentType, rawBuffer);

    const maskedHeaders = _masker.scrubHeaders(
      Object.fromEntries(upstreamResponse.headers.entries())
    );

    let responseMsg: KeyholeResponse;
    let redactionLayers: string[] | undefined;

    if (isBinary) {
      responseMsg = {
        id: request.id,
        status: upstreamResponse.status,
        headers: maskedHeaders,
        body: '',
        bodyBase64: rawBuffer.toString('base64'),
        bodyEncoding: 'base64',
        redacted: false
      };
    } else {
      const rawBody = rawBuffer.toString('utf-8');
      const { body: maskedBody, redacted, layers, heuristicKeys } =
        _masker.maskBody(rawBody, request.service);
      redactionLayers = layers;
      responseMsg = {
        id: request.id,
        status: upstreamResponse.status,
        headers: maskedHeaders,
        body: maskedBody,
        bodyEncoding: 'utf8',
        redacted
      };

      if (heuristicKeys.length > 0) {
        logger.warn('response.heuristic_redaction', {
          service: request.service,
          keys: heuristicKeys,
          redaction_count: heuristicKeys.length,
        });
      }
    }

    const duration = Date.now() - startTime;
    logger.log({
      event: 'request.proxied',
      service: request.service,
      method: request.method,
      path: sanitizePathForLog(request.path, service),
      status: upstreamResponse.status,
      duration_ms: duration,
      redacted: responseMsg.redacted,
      redaction_layers: redactionLayers,
      agent: request.agent
    });

    sendResponse(conn, responseMsg);
  } catch (err: any) {
    const duration = Date.now() - startTime;
    logger.error('request.failed', {
      service: request.service,
      method: request.method,
      path: request.path,
      duration_ms: duration,
      error: err.message,
      agent: request.agent
    });

    sendResponse(conn, {
      id: request.id,
      status: 502,
      headers: {},
      body: '',
      bodyEncoding: 'utf8',
      error: `Upstream request failed: ${err.message}`
    });
  }
}

async function fetchWithRedirectPolicy(
  url: string,
  options: RequestInit,
  serviceName: string,
  builder: RequestBuilder,
  redirectCount = 0
): Promise<Response> {
  if (redirectCount > MAX_REDIRECTS) {
    throw new Error(`Too many redirects (>${MAX_REDIRECTS})`);
  }

  const response = await fetch(url, { ...options, redirect: 'manual' });

  if (![301, 302, 303, 307, 308].includes(response.status)) {
    return response;
  }

  const location = response.headers.get('location');
  if (!location) return response;

  const redirectUrl = new URL(location, url);
  const redirectHost = redirectUrl.hostname;

  const service = builder.getServiceConfig(serviceName);
  const isTrusted = service.domains.some(
    (d) => (typeof d === 'string' ? d : d.host) === redirectHost
  );

  if (isTrusted) {
    const authHeaders = builder.buildAuthHeaders(serviceName);
    const currentHeaders = {
      ...(options.headers as Record<string, string>),
      ...authHeaders
    };
    builder.injectQueryParamAuth(redirectUrl, serviceName);

    return fetchWithRedirectPolicy(
      redirectUrl.toString(),
      { ...options, headers: currentHeaders },
      serviceName,
      builder,
      redirectCount + 1
    );
  } else {
    // Untrusted domain – strip everything except safe metadata
    const whitelist = ['content-type', 'accept', 'user-agent'];
    const safeHeaders: Record<string, string> = {};
    const inputHeaders = options.headers as Record<string, string>;

    for (const key of Object.keys(inputHeaders || {})) {
      if (whitelist.includes(key.toLowerCase())) {
        safeHeaders[key] = inputHeaders[key];
      }
    }

    // Strip query_param auth if applicable
    if (service.auth.type === 'query_param') {
      redirectUrl.searchParams.delete(
        (service.auth as { type: 'query_param'; param_name: string }).param_name
      );
    }

    return fetchWithRedirectPolicy(
      redirectUrl.toString(),
      { ...options, headers: safeHeaders },
      serviceName,
      builder,
      redirectCount + 1
    );
  }
}

function sendResponse(conn: net.Socket, response: KeyholeResponse): void {
  const payload = Buffer.from(JSON.stringify(response), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  conn.write(Buffer.concat([header, payload]));
}
