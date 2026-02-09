/**
 * Credential patterns used across all Secretless integrations.
 * Shared between scanner, hooks, and MCP server.
 */

export interface CredentialPattern {
  id: string;
  name: string;
  regex: RegExp;
  envPrefix: string;
}

export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  { id: 'anthropic', name: 'Anthropic API Key', regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/, envPrefix: 'ANTHROPIC_API_KEY' },
  { id: 'openai-proj', name: 'OpenAI Project Key', regex: /sk-proj-[a-zA-Z0-9]{20,}/, envPrefix: 'OPENAI_API_KEY' },
  { id: 'openai-legacy', name: 'OpenAI Legacy Key', regex: /sk-[a-zA-Z0-9]{48,}/, envPrefix: 'OPENAI_API_KEY' },
  { id: 'aws-access', name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, envPrefix: 'AWS_ACCESS_KEY_ID' },
  { id: 'github-pat', name: 'GitHub Token', regex: /ghp_[a-zA-Z0-9]{36}/, envPrefix: 'GITHUB_TOKEN' },
  { id: 'github-fine', name: 'GitHub Fine-Grained PAT', regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, envPrefix: 'GITHUB_TOKEN' },
  { id: 'slack', name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, envPrefix: 'SLACK_TOKEN' },
  { id: 'google', name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/, envPrefix: 'GOOGLE_API_KEY' },
  { id: 'stripe', name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/, envPrefix: 'STRIPE_SECRET_KEY' },
  { id: 'sendgrid', name: 'SendGrid Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, envPrefix: 'SENDGRID_API_KEY' },
  { id: 'supabase', name: 'Supabase Service Key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}/, envPrefix: 'SUPABASE_SERVICE_ROLE_KEY' },
  { id: 'azure', name: 'Azure Key', regex: /[a-zA-Z0-9+/]{43}=/, envPrefix: 'AZURE_API_KEY' },
];

/** File patterns that should never be read by AI tools */
export const SECRET_FILE_PATTERNS: string[] = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '*.key',
  '*.pem',
  '*.p12',
  '*.pfx',
  '*.crt',
  '.aws/credentials',
  '.ssh/*',
  '.docker/config.json',
  '.git-credentials',
  '.npmrc',
  '.pypirc',
  '*.tfstate',
  '*.tfvars',
  'secrets/',
  'credentials/',
  '.opena2a/secretless-ai/',
];

/** Config files that may contain hardcoded secrets */
export const CONFIG_FILES = [
  'config.json', 'config.yaml', 'config.yml',
  '.env', '.env.local',
  'package.json', 'mcp.json',
  'CLAUDE.md',
  '.openclaw/config.json', '.moltbot/config.json',
  'openclaw.json', 'moltbot.json',
  '.curse/mcp.json', '.vscode/mcp.json',
  '.claude/settings.json',
  '.cursor/settings.json',
  '.github/copilot-instructions.md',
];
