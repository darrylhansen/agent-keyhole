import net from 'net';
import type { KeyholeRequest, KeyholeResponse } from '../sidecar/ipc-types.js';

export class IPCClient {
  private socketPath: string;
  private ott: string;
  private pending = new Map<
    string,
    {
      resolve: (res: KeyholeResponse) => void;
      reject: (err: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private conn: net.Socket | null = null;
  private buffer = Buffer.alloc(0);
  private reconnecting = false;
  private reconnectAttempts = 0;
  private timeout: number;
  private agent?: string;

  private static MAX_RECONNECT_ATTEMPTS = 3;
  private static RECONNECT_DELAY_MS = 500;

  constructor(socketPath: string, ott: string, options?: { timeout?: number; agent?: string }) {
    this.socketPath = socketPath;
    this.ott = ott;
    this.timeout = options?.timeout || 30_000;
    this.agent = options?.agent;
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.conn = net.createConnection(this.socketPath, () => {
        this.reconnectAttempts = 0;
        resolve();
      });
      // Capture the socket so all handlers only fire for the current connection.
      // Without this, updateConnection() creates a race: the old socket's async
      // events fire after this.conn is reassigned to the new socket, causing
      // handlers to act on the wrong connection context.
      const socket = this.conn;
      socket.on('close', () => {
        if (this.conn === socket) this.handleDisconnect();
      });
      socket.on('error', (err) => {
        if (this.conn === socket && !this.reconnecting) reject(err);
      });
      socket.on('data', (data: Buffer) => {
        if (this.conn === socket) this.onData(data);
      });
    });
  }

  private async handleDisconnect(): Promise<void> {
    if (this.reconnecting) return;
    // If conn was explicitly destroyed (via disconnect()), do nothing
    if (!this.conn) return;

    this.reconnecting = true;
    this.conn = null;

    while (this.reconnectAttempts < IPCClient.MAX_RECONNECT_ATTEMPTS) {
      this.reconnectAttempts++;
      await new Promise((r) =>
        setTimeout(r, IPCClient.RECONNECT_DELAY_MS * this.reconnectAttempts)
      );

      try {
        await this.connect();
        this.reconnecting = false;
        return;
      } catch {
        // Will retry
      }
    }

    // All reconnect attempts exhausted
    this.reconnecting = false;
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(
        new Error(
          'IPC connection lost and reconnect failed after ' +
            `${IPCClient.MAX_RECONNECT_ATTEMPTS} attempts`
        )
      );
    }
    this.pending.clear();
  }

  private onData(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);

    while (this.buffer.length >= 4) {
      const payloadLength = this.buffer.readUInt32BE(0);
      if (this.buffer.length < 4 + payloadLength) break;

      const payload = this.buffer.subarray(4, 4 + payloadLength);
      this.buffer = this.buffer.subarray(4 + payloadLength);

      let response: KeyholeResponse;
      try {
        response = JSON.parse(payload.toString('utf-8')) as KeyholeResponse;
      } catch {
        // Corrupted or partial message — discard and continue reading.
        // This can occur if the sidecar crashes mid-write or the IPC pipe
        // delivers a truncated frame.
        continue;
      }

      const pending = this.pending.get(response.id);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(response.id);
        if (response.error) {
          pending.reject(new Error(response.error));
        } else {
          pending.resolve(response);
        }
      }
    }
  }

  async send(
    request: Omit<KeyholeRequest, 'ott'>
  ): Promise<KeyholeResponse> {
    if (!this.conn) throw new Error('Not connected');

    const fullRequest: KeyholeRequest = {
      ...request,
      ott: this.ott,
      agent: request.agent || this.agent
    };
    const payload = Buffer.from(JSON.stringify(fullRequest), 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.has(request.id)) {
          this.pending.delete(request.id);
          reject(
            new Error(
              `Request timed out: ${request.service} ${request.method} ${request.path}`
            )
          );
        }
      }, this.timeout);

      this.pending.set(request.id, { resolve, reject, timer });
      this.conn!.write(Buffer.concat([header, payload]));
    });
  }

  async disconnect(): Promise<void> {
    if (this.conn) {
      const conn = this.conn;
      this.conn = null; // Set to null BEFORE destroy to signal intentional disconnect
      conn.destroy();
    }
    // Clean up pending requests
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('IPC client disconnected'));
    }
    this.pending.clear();
  }

  /** Update connection after sidecar restart (new OTT and socket) */
  async updateConnection(socketPath: string, ott: string): Promise<void> {
    await this.disconnect();
    this.socketPath = socketPath;
    this.ott = ott;
    this.reconnectAttempts = 0;
    this.buffer = Buffer.alloc(0);
    await this.connect();
  }
}
