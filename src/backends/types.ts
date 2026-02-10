/**
 * Pluggable secret backend interface.
 * Each backend resolves secrets from a different source.
 * Zero mandatory deps — backend SDKs are optional peer dependencies.
 */
export interface SecretBackend {
  /** Backend name (e.g., "vault", "aws-sm", "env") */
  readonly name: string;

  /** Resolve one or more secrets by path/name. Returns key-value pairs. */
  resolve(path: string): Promise<Record<string, string>>;

  /** Check if the backend is available and authenticated */
  healthCheck(): Promise<BackendHealth>;
}

export interface BackendHealth {
  healthy: boolean;
  latencyMs: number;
  message?: string;
}

/** Backend configuration from secretless config file */
export interface BackendConfig {
  /** Backend type */
  type: BackendType;
  /** Backend-specific config */
  config?: Record<string, unknown>;
  /** Priority (lower = preferred, default: 100) */
  priority?: number;
  /** Path prefix this backend handles (e.g., "vault/", "aws/") */
  prefix?: string;
}

export type BackendType = 'env' | 'local' | 'vault' | 'aws-sm' | '1password';

/** Access audit entry */
export interface AccessAuditEntry {
  timestamp: string;
  backend: string;
  path: string;
  action: 'resolve' | 'healthCheck' | 'migrate';
  success: boolean;
  latencyMs: number;
}
