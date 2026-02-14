import crypto from 'crypto';
import { IPCClient } from './ipc-client.js';
import type { KeyholeResponse } from '../sidecar/ipc-types.js';

export type KeyholeClient = (
  path: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  }
) => Promise<Response>;

export function createClient(
  ipc: IPCClient,
  serviceName: string
): KeyholeClient {
  return async (path: string, init?: any): Promise<Response> => {
    const id = crypto.randomUUID();

    const response = await ipc.send({
      id,
      service: serviceName,
      method: init?.method || 'GET',
      path,
      headers: init?.headers || {},
      body: init?.body,
      bodyEncoding: 'utf8'
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
  };
}
