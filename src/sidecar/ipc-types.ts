export interface KeyholeRequest {
  id: string;
  ott: string;
  service: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string;
  bodyBase64?: string;
  bodyEncoding: 'utf8' | 'base64';
  agent?: string;
}

export interface KeyholeResponse {
  id: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  bodyBase64?: string;
  bodyEncoding: 'utf8' | 'base64';
  error?: string;
  redacted?: boolean;
}

export interface BootstrapMessage {
  type: 'bootstrap';
  ott: string;
  config: any;
  vaultPassphrase?: string;
  agent?: string;
  agentServices?: string[];
}

export interface UnlockMessage {
  type: 'unlock';
  passphrase: string;
}

export interface ShutdownMessage {
  type: 'shutdown';
}

export type SidecarMessage = BootstrapMessage | UnlockMessage | ShutdownMessage;

export interface ReadyMessage {
  type: 'ready';
  socketPath: string;
  state: 'ready' | 'pending_unlock';
}

export interface ErrorMessage {
  type: 'error';
  message: string;
}

export interface UnlockedMessage {
  type: 'unlocked';
  state: 'ready';
}

export type SidecarResponse = ReadyMessage | ErrorMessage | UnlockedMessage;
