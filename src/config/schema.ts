export interface KeyholeConfig {
  services: Record<string, ServiceConfig>;
  agents?: Record<string, AgentConfig>;
  logging?: LoggingConfig;
  alerting?: AlertingConfig;
  socket_dir?: string;
  vaultPath?: string;
}

export interface ServiceConfig {
  domains: Array<string | DomainWithPrefix>;
  auth: AuthConfig;
  placeholder?: string;
  sdk_env?: Record<string, string>;
  headers?: Record<string, string>;
  response_masking?: ResponseMaskingConfig;
  base_url?: string;
}

export interface DomainWithPrefix {
  host: string;
  path_prefix: string;
}

export type AuthConfig =
  | { type: 'bearer'; secret_ref: string }
  | { type: 'basic'; secret_ref: string; username?: string }
  | {
      type: 'query_param';
      param_name: string;
      secret_ref: string;
    }
  | {
      type: 'custom_header';
      header_name: string;
      secret_ref: string;
    };

export interface ResponseMaskingConfig {
  patterns?: string[];
  json_paths?: string[];
  streaming?: 'stream' | 'buffer';
  streaming_window_cap?: number;
  heuristic?: HeuristicConfig;
}

export interface HeuristicConfig {
  enabled?: boolean;
  min_length?: number;
  min_entropy?: number;
  additional_key_names?: string[];
}

export interface AgentConfig {
  services: string[];
}

export interface LoggingConfig {
  output?: 'stderr' | 'stdout' | string;
  level?: 'debug' | 'info' | 'warn' | 'error';
  verbose?: boolean;
}

export interface AlertingConfig {
  webhook_url?: string;
  message_prefix?: string;
}

export interface ParsedConfig extends KeyholeConfig {
  _domainToService: Map<string, string>;
  _secretRefs: string[];
}
