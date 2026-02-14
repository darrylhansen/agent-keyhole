import { Readable, Writable } from 'stream';
import crypto from 'crypto';
import { IPCClient } from './ipc-client.js';
import { isBodyBinary } from './binary-detect.js';
import type { KeyholeRequest } from '../sidecar/ipc-types.js';

export class FakeClientRequest extends Writable {
  private bodyChunks: Buffer[] = [];
  private totalSize = 0;
  private ipc: IPCClient;
  private service: string;
  private method: string;
  private path: string;
  private _headers: Record<string, string>;
  private responseCallback?: (res: any) => void;

  public headersSent = false;
  public finished = false;
  public aborted = false;

  private static MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB

  constructor(
    ipc: IPCClient,
    service: string,
    method: string,
    path: string,
    headers: Record<string, string>,
    callback?: (res: any) => void
  ) {
    super();
    this.ipc = ipc;
    this.service = service;
    this.method = method;
    this.path = path;
    this._headers = headers;
    this.responseCallback = callback;
  }

  /**
   * Writable stream _write implementation.
   * This enables pipe() support: readable.pipe(fakeRequest) works correctly.
   */
  _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    const buf = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk, encoding);
    this.totalSize += buf.length;

    if (this.totalSize > FakeClientRequest.MAX_BODY_SIZE) {
      const err = new Error(
        `Request body exceeds Keyhole limit (${FakeClientRequest.MAX_BODY_SIZE} bytes). ` +
          `For large uploads, use keyhole.createClient() with streaming support (v1.5).`
      );
      callback(err);
      return;
    }

    this.bodyChunks.push(buf);
    callback(null);
  }

  /**
   * _final is called by the Writable base class when end() is called.
   * This is where we send the accumulated body to the sidecar.
   */
  _final(callback: (error?: Error | null) => void): void {
    this.headersSent = true;
    this.finished = true;

    const rawBody = Buffer.concat(this.bodyChunks);
    const id = crypto.randomUUID();

    // Determine encoding: binary bodies must be Base64 to avoid corruption
    const contentType =
      this._headers['content-type'] || this._headers['Content-Type'];
    const binary = isBodyBinary(contentType, rawBody);

    const ipcMessage: Omit<KeyholeRequest, 'ott'> = {
      id,
      service: this.service,
      method: this.method,
      path: this.path,
      headers: this._headers,
      bodyEncoding: binary ? 'base64' : 'utf8'
    };

    if (binary) {
      ipcMessage.bodyBase64 = rawBody.toString('base64');
    } else {
      ipcMessage.body = rawBody.toString('utf-8');
    }

    this.ipc
      .send(ipcMessage)
      .then((response) => {
        const readable = new Readable({
          read() {
            if (response.bodyEncoding === 'base64' && response.bodyBase64) {
              this.push(Buffer.from(response.bodyBase64, 'base64'));
            } else {
              this.push(response.body);
            }
            this.push(null);
          }
        });

        (readable as any).statusCode = response.status;
        (readable as any).headers = response.headers;
        (readable as any).statusMessage = '';

        if (this.responseCallback) this.responseCallback(readable);
        this.emit('response', readable);
        callback(null);
      })
      .catch((err) => {
        callback(err);
      });
  }

  /**
   * _destroy is called when destroy() is called or on error.
   */
  _destroy(
    err: Error | null,
    callback: (error?: Error | null) => void
  ): void {
    this.aborted = true;
    this.bodyChunks = [];
    this.totalSize = 0;
    callback(err);
  }

  abort(): void {
    this.aborted = true;
    this.destroy();
    this.emit('abort');
  }

  setHeader(name: string, value: string): void {
    this._headers[name] = value;
  }

  getHeader(name: string): string | undefined {
    return this._headers[name];
  }

  removeHeader(name: string): void {
    delete this._headers[name];
  }

  // No-ops: meaningless in a proxied context but SDKs may call them
  setTimeout(_ms: number, _cb?: () => void): this {
    return this;
  }
  setNoDelay(_noDelay?: boolean): void {}
  setSocketKeepAlive(_enable?: boolean, _initial?: number): void {}
  flushHeaders(): void {
    this.headersSent = true;
  }
}
