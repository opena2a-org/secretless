export { discoverMcpConfigs, type McpClient, type McpConfigFile, type McpServerEntry } from './discover';
export { classifyEnvVars, type ClassifiedEnv } from './classify';
export { McpVault } from './vault';
export { rewriteConfig, restoreConfig, type RewriteResult } from './rewrite';
export { protectMcp, type ProtectOptions, type ProtectResult, type ProtectedServer } from './protect';
export { installWrapper, getWrapperCommand, type WrapperCommand } from './install-wrapper';
