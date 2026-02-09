/**
 * Initialize Secretless for a project.
 * Auto-detects AI tools and installs appropriate protections.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, toolDisplayName, type AITool } from './detect';
import { SECRET_FILE_PATTERNS, CREDENTIAL_PATTERNS, CONFIG_FILES } from './patterns';

interface InitResult {
  toolsDetected: AITool[];
  toolsConfigured: AITool[];
  filesCreated: string[];
  filesModified: string[];
  secretsFound: number;
}

/**
 * Initialize Secretless protections for the project.
 * This is the main entry point called by `npx @opena2a/secretless init`.
 */
export function init(projectDir: string): InitResult {
  const result: InitResult = {
    toolsDetected: [],
    toolsConfigured: [],
    filesCreated: [],
    filesModified: [],
    secretsFound: 0,
  };

  // Detect AI tools
  const detected = detectAITools(projectDir);
  result.toolsDetected = detected.map(d => d.tool);

  // If no tools detected, default to Claude Code (most common for npx users)
  if (detected.length === 0) {
    detected.push({
      tool: 'claude-code',
      configDir: '.claude',
      settingsFile: '.claude/settings.json',
      hooksSupported: true,
    });
  }

  // Quick scan for existing secrets
  result.secretsFound = quickScan(projectDir);

  // Configure each detected tool
  for (const tool of detected) {
    switch (tool.tool) {
      case 'claude-code':
        configureClaudeCode(projectDir, result);
        break;
      case 'cursor':
        configureCursor(projectDir, result);
        break;
      case 'copilot':
        configureCopilot(projectDir, result);
        break;
      case 'windsurf':
        configureWindsurf(projectDir, result);
        break;
      case 'cline':
        configureCline(projectDir, result);
        break;
      case 'aider':
        configureAider(projectDir, result);
        break;
    }
    result.toolsConfigured.push(tool.tool);
  }

  return result;
}

// ============================================================================
// Claude Code Configuration
// ============================================================================

function configureClaudeCode(projectDir: string, result: InitResult): void {
  const claudeDir = path.join(projectDir, '.claude');
  const hooksDir = path.join(claudeDir, 'hooks');

  // Ensure directories exist
  fs.mkdirSync(hooksDir, { recursive: true });

  // 1. Install PreToolUse hook
  const hookPath = path.join(hooksDir, 'secretless-guard.sh');
  if (!fs.existsSync(hookPath)) {
    fs.writeFileSync(hookPath, generateClaudeHookScript(), { mode: 0o755 });
    result.filesCreated.push('.claude/hooks/secretless-guard.sh');
  }

  // 2. Update settings.json with hook config and deny rules
  const settingsPath = path.join(claudeDir, 'settings.json');
  const settings = readJsonFile(settingsPath) || {};

  // Add hooks config
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  const hookExists = settings.hooks.PreToolUse.some(
    (h: any) => h.hooks?.some((hh: any) => hh.command?.includes('secretless-guard'))
  );

  if (!hookExists) {
    settings.hooks.PreToolUse.push({
      matcher: 'Read|Grep|Glob|Bash|Write|Edit',
      hooks: [{
        type: 'command',
        command: '"$CLAUDE_PROJECT_DIR"/.claude/hooks/secretless-guard.sh',
      }],
    });
    result.filesModified.push('.claude/settings.json');
  }

  // Add deny rules for secret files
  if (!settings.permissions) settings.permissions = {};
  if (!settings.permissions.deny) settings.permissions.deny = [];

  const denyRules = [
    'Read(.env*)',
    'Read(*.key)',
    'Read(*.pem)',
    'Read(*.p12)',
    'Read(*.pfx)',
    'Read(*.tfstate)',
    'Read(*.tfvars)',
    'Read(.aws/credentials)',
    'Read(.ssh/*)',
    'Bash(cat .env*)',
    'Bash(cat *.key)',
    'Bash(echo $*SECRET*)',
    'Bash(echo $*PASSWORD*)',
    'Bash(echo $*API_KEY*)',
  ];

  for (const rule of denyRules) {
    if (!settings.permissions.deny.includes(rule)) {
      settings.permissions.deny.push(rule);
    }
  }

  writeJsonFile(settingsPath, settings);

  // 3. Add Secretless instructions to CLAUDE.md
  const claudeMdPath = path.join(projectDir, 'CLAUDE.md');
  addSecretlessInstructions(claudeMdPath, 'claude-code', result);
}

// ============================================================================
// Cursor Configuration
// ============================================================================

function configureCursor(projectDir: string, result: InitResult): void {
  const rulesPath = path.join(projectDir, '.cursorrules');
  addSecretlessInstructions(rulesPath, 'cursor', result);
}

// ============================================================================
// GitHub Copilot Configuration
// ============================================================================

function configureCopilot(projectDir: string, result: InitResult): void {
  const githubDir = path.join(projectDir, '.github');
  fs.mkdirSync(githubDir, { recursive: true });

  const instructionsPath = path.join(githubDir, 'copilot-instructions.md');
  addSecretlessInstructions(instructionsPath, 'copilot', result);
}

// ============================================================================
// Windsurf Configuration
// ============================================================================

function configureWindsurf(projectDir: string, result: InitResult): void {
  const rulesPath = path.join(projectDir, '.windsurfrules');
  addSecretlessInstructions(rulesPath, 'windsurf', result);
}

// ============================================================================
// Cline Configuration
// ============================================================================

function configureCline(projectDir: string, result: InitResult): void {
  const rulesPath = path.join(projectDir, '.clinerules');
  addSecretlessInstructions(rulesPath, 'cline', result);
}

// ============================================================================
// Aider Configuration
// ============================================================================

function configureAider(projectDir: string, result: InitResult): void {
  const ignorePath = path.join(projectDir, '.aiderignore');
  const existing = fs.existsSync(ignorePath) ? fs.readFileSync(ignorePath, 'utf-8') : '';

  if (!existing.includes('# Secretless')) {
    const secretPatterns = [
      '',
      '# Secretless: keep secrets out of AI context',
      '.env',
      '.env.*',
      '*.key',
      '*.pem',
      '*.p12',
      '*.pfx',
      '*.tfstate',
      '*.tfvars',
      '.aws/',
      '.ssh/',
      'secrets/',
      'credentials/',
    ].join('\n');

    fs.writeFileSync(ignorePath, existing + secretPatterns + '\n');
    if (existing) {
      result.filesModified.push('.aiderignore');
    } else {
      result.filesCreated.push('.aiderignore');
    }
  }
}

// ============================================================================
// Shared Utilities
// ============================================================================

const SECRETLESS_MARKER = '<!-- secretless:managed -->';

const SECRETLESS_INSTRUCTIONS = `
${SECRETLESS_MARKER}
## Secretless Mode

This project uses Secretless to protect credentials from AI context.

**Blocked file patterns** (never read, write, or reference):
- \`.env\`, \`.env.*\` — environment variable files
- \`*.key\`, \`*.pem\`, \`*.p12\`, \`*.pfx\` — private key files
- \`.aws/credentials\`, \`.ssh/*\` — cloud/SSH credentials
- \`*.tfstate\`, \`*.tfvars\` — Terraform state with secrets
- \`secrets/\`, \`credentials/\` — secret directories

**If you need a credential:**
1. Ask the user to set it as an environment variable
2. Reference it via \`process.env.VAR_NAME\` or \`os.environ["VAR_NAME"]\`
3. Never hardcode credentials in source files

**If you find a hardcoded credential:**
1. Replace it with an environment variable reference
2. Add the variable name to \`.env.example\`
3. Warn the user to rotate the exposed credential
`;

function addSecretlessInstructions(filePath: string, tool: string, result: InitResult): void {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : '';

  if (existing.includes(SECRETLESS_MARKER)) {
    return; // Already configured
  }

  fs.writeFileSync(filePath, existing + SECRETLESS_INSTRUCTIONS);
  if (existing) {
    result.filesModified.push(path.relative(process.cwd(), filePath));
  } else {
    result.filesCreated.push(path.relative(process.cwd(), filePath));
  }
}

function generateClaudeHookScript(): string {
  // Build pattern list for the shell script
  const filePatterns = [
    '.env', '.env.local', '.env.development', '.env.production', '.env.staging',
    '.key', '.pem', '.p12', '.pfx', '.crt',
    'credentials', '.aws/credentials', '.ssh/',
    '.docker/config.json', '.git-credentials',
    '.npmrc', '.pypirc',
    '.tfstate', '.tfvars',
    'secrets/', '.opena2a/secretless/',
  ];

  return `#!/bin/bash
# Secretless Guard — PreToolUse hook for Claude Code
# Blocks file access to secrets before they enter AI context.
# Managed by @opena2a/secretless. Do not edit manually.

set -euo pipefail

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | grep -o '"tool_name":"[^"]*"' | head -1 | cut -d'"' -f4)

# Extract file path from tool input (handles Read, Grep, Glob, Edit, Write)
FILE_PATH=$(echo "$INPUT" | grep -o '"file_path":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$FILE_PATH" ]; then
  FILE_PATH=$(echo "$INPUT" | grep -o '"path":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

# For Bash tool, check the command for secret access patterns
if [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4)
  # Block commands that dump secret files
  if echo "$COMMAND" | grep -qiE '(cat|head|tail|less|more|type)\\s+.*\\.(env|key|pem|p12|pfx)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that reads secret files"}}'
    exit 0
  fi
  # Block commands that echo secret env vars
  if echo "$COMMAND" | grep -qiE 'echo\\s+.*\\$(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that exposes secret environment variables"}}'
    exit 0
  fi
  exit 0
fi

# Skip if no file path found
if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Normalize path for matching
BASENAME=$(basename "$FILE_PATH")
LOWER_PATH=$(echo "$FILE_PATH" | tr '[:upper:]' '[:lower:]')

# Block patterns
${filePatterns.map(p => {
    if (p.startsWith('.') && !p.includes('/')) {
      // Extension or dotfile match
      if (p.includes('*')) {
        return `# Match ${p}\nif echo "$BASENAME" | grep -qE '\\${p.replace('*', '.*')}$'; then BLOCKED=1; REASON="${p}"; fi`;
      }
      return `# Match ${p}\nif [ "$BASENAME" = "${p}" ] || echo "$BASENAME" | grep -qE '^\\${p}'; then BLOCKED=1; REASON="${p}"; fi`;
    }
    // Path fragment match
    return `# Match ${p}\nif echo "$LOWER_PATH" | grep -qi '${p}'; then BLOCKED=1; REASON="${p}"; fi`;
  }).join('\n')}

if [ "\${BLOCKED:-0}" = "1" ]; then
  echo "{\\"hookSpecificOutput\\":{\\"hookEventName\\":\\"PreToolUse\\",\\"permissionDecision\\":\\"deny\\",\\"permissionDecisionReason\\":\\"Secretless: blocked access to secret file matching pattern '$REASON'\\"}}"
  exit 0
fi

exit 0
`;
}

function quickScan(projectDir: string): number {
  let count = 0;
  for (const configFile of CONFIG_FILES) {
    const fullPath = path.join(projectDir, configFile);
    if (!fs.existsSync(fullPath)) continue;

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > 10 * 1024 * 1024) continue; // Skip files > 10MB

      const content = fs.readFileSync(fullPath, 'utf-8');
      for (const line of content.split('\n')) {
        if (line.length > 4096) continue; // ReDoS protection
        for (const pattern of CREDENTIAL_PATTERNS) {
          if (pattern.regex.test(line)) {
            count++;
            break; // One finding per line
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }
  return count;
}

function readJsonFile(filePath: string): any {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return null;
  }
}

function writeJsonFile(filePath: string, data: any): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}
