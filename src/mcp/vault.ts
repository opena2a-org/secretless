/**
 * MCP Vault — encrypted secret storage namespaced by client/server.
 *
 * Thin wrapper around LocalBackend that stores secrets with key
 * `mcp/{client}/{server}/{envKey}`, providing per-server isolation.
 */

import { LocalBackend } from '../backends/local';

const MCP_PREFIX = 'mcp';

/** Validates client/server names to prevent path traversal. */
const SAFE_NAME = /^[a-zA-Z0-9_\-]+$/;

function validateName(label: string, value: string): void {
  if (!SAFE_NAME.test(value)) {
    throw new Error(`Invalid ${label} name: "${value}". Only alphanumeric, dash, and underscore allowed.`);
  }
}

export class McpVault {
  private readonly backend: LocalBackend;

  constructor(config?: Record<string, unknown>) {
    this.backend = new LocalBackend(config);
  }

  /**
   * Store secrets for a specific MCP server.
   * Each secret is stored with key `mcp/{client}/{server}/{envKey}`.
   */
  async storeServerSecrets(
    client: string,
    server: string,
    secrets: Record<string, string>,
  ): Promise<void> {
    validateName('client', client);
    validateName('server', server);
    for (const [envKey, value] of Object.entries(secrets)) {
      const storeKey = `${MCP_PREFIX}/${client}/${server}/${envKey}`;
      await this.backend.store(storeKey, value);
    }
  }

  /**
   * Retrieve all secrets for a specific MCP server.
   * Returns a map of env var names to their values.
   */
  async getServerSecrets(
    client: string,
    server: string,
  ): Promise<Record<string, string>> {
    validateName('client', client);
    validateName('server', server);
    const prefix = `${MCP_PREFIX}/${client}/${server}`;
    const raw = await this.backend.resolve(prefix);

    const result: Record<string, string> = {};
    for (const [fullKey, value] of Object.entries(raw)) {
      // Strip prefix to get just the env var name
      const envKey = fullKey.slice(prefix.length + 1);
      if (envKey) {
        result[envKey] = value;
      }
    }
    return result;
  }

  /**
   * Remove all secrets for a specific MCP server.
   */
  async removeServerSecrets(client: string, server: string): Promise<void> {
    validateName('client', client);
    validateName('server', server);
    const prefix = `${MCP_PREFIX}/${client}/${server}`;
    const existing = await this.backend.resolve(prefix);

    for (const key of Object.keys(existing)) {
      await this.backend.delete(key);
    }
  }

  /**
   * List all stored server entries, grouped by client and server.
   * Returns the number of secret keys stored for each client/server pair.
   */
  async listEntries(): Promise<Array<{ client: string; server: string; keyCount: number }>> {
    const all = await this.backend.resolve(MCP_PREFIX);

    // Group by client/server
    const groups = new Map<string, number>();

    for (const fullKey of Object.keys(all)) {
      // Keys are in format: mcp/{client}/{server}/{envKey}
      const parts = fullKey.split('/');
      if (parts.length < 4) continue;

      const groupKey = `${parts[1]}/${parts[2]}`;
      groups.set(groupKey, (groups.get(groupKey) ?? 0) + 1);
    }

    const entries: Array<{ client: string; server: string; keyCount: number }> = [];
    for (const [groupKey, keyCount] of groups) {
      const [client, server] = groupKey.split('/');
      entries.push({ client, server, keyCount });
    }

    return entries;
  }
}
