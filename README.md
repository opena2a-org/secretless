> **[OpenA2A](https://opena2a.org)**: [AIM](https://github.com/opena2a-org/agent-identity-management) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [OASB](https://github.com/opena2a-org/oasb) · [ARP](https://github.com/opena2a-org/arp) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

# Secretless AI

[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

One command to keep secrets out of AI LLMs. Works with Claude Code, Cursor, Copilot, Windsurf, Cline, and Aider.

Part of the [OpenA2A](https://opena2a.org) ecosystem — open-source security for AI agents.

```bash
npx secretless-ai init
```

## MCP Secret Protection

Every MCP server config has plaintext API keys sitting in JSON files on your laptop. The LLM sees them. Secretless encrypts them.

```bash
npx secretless-ai protect-mcp
```

```
  Secretless MCP Protection

  Scanned 1 client(s)

  + claude-desktop/browserbase
      BROWSERBASE_API_KEY (encrypted)
  + claude-desktop/github
      GITHUB_PERSONAL_ACCESS_TOKEN (encrypted)
  + claude-desktop/stripe
      STRIPE_SECRET_KEY (encrypted)

  3 secret(s) encrypted across 3 server(s).

  MCP servers will start normally — no workflow changes needed.
```

**What happens:**

1. Scans MCP configs across Claude Desktop, Cursor, Claude Code, VS Code, and Windsurf
2. Identifies which env vars are secrets (key name patterns + value regex matching)
3. Encrypts secrets into a local AES-256-GCM vault (`~/.secretless-ai/mcp-vault/`)
4. Rewrites configs to use the `secretless-mcp` wrapper — decrypts at runtime, injects as env vars
5. Non-secret env vars (URLs, org names, regions) stay in the config untouched

**Before:**
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["@github/mcp-server"],
      "env": {
        "GITHUB_TOKEN": "ghp_plaintext_visible_to_LLM",
        "GITHUB_ORG": "my-org"
      }
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "github": {
      "command": "secretless-mcp",
      "args": ["--server", "github", "--client", "claude-desktop", "--", "npx", "@github/mcp-server"],
      "env": {
        "GITHUB_ORG": "my-org"
      }
    }
  }
}
```

The secret moves to the encrypted vault. The wrapper decrypts it at startup (<10ms overhead) and passes it to the MCP server as an env var. The LLM never sees it.

**Other MCP commands:**

```bash
npx secretless-ai mcp-status      # Show which servers are protected/exposed
npx secretless-ai mcp-unprotect   # Restore original configs from backup
```

---

## AI Context Protection

AI coding tools read your files to provide context. That includes `.env` files, API keys in config, SSH keys, and cloud credentials. Once a secret enters an AI context window, it's sent to a remote API — and you can't take it back.

## How It Works

Secretless auto-detects which AI tools you use and installs the right protections for each one:

| Tool | Protection Method |
|------|------------------|
| **Claude Code** | PreToolUse hook (blocks file reads before they happen) + deny rules + CLAUDE.md instructions |
| **Cursor** | `.cursorrules` instructions |
| **GitHub Copilot** | `.github/copilot-instructions.md` instructions |
| **Windsurf** | `.windsurfrules` instructions |
| **Cline** | `.clinerules` instructions |
| **Aider** | `.aiderignore` file patterns |

Claude Code gets the strongest protection because it supports [hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) — a shell script runs *before* every file read and blocks access to secret files at the tool level. Other tools get instruction-based protection.

## Quick Start

```bash
# In any project directory
npx secretless-ai init
```

Output:

```
  Secretless v0.6.0
  Keeping secrets out of AI

  Detected:
    + Claude Code
    + Cursor

  Configured:
    * Claude Code
    * Cursor

  Created:
    + .claude/hooks/secretless-guard.sh
    + CLAUDE.md

  Modified:
    ~ .claude/settings.json
    ~ .cursorrules

  Done. Secrets are now blocked from AI context.
```

## Moving Keys from AI Context to Env Vars

The safest setup: keys live in environment variables, AI tools reference them by name.

**Step 1: Move keys to the correct shell profile**

Non-interactive subprocesses (Claude Code's Bash tool, CI/CD, Docker) don't source interactive-only profiles. Use the right file for your platform:

| Platform | Shell | Correct File | Why |
|----------|-------|-------------|-----|
| macOS | zsh | `~/.zshenv` | Sourced by ALL shells (interactive + non-interactive) |
| Linux | bash | `~/.bashrc` | Sourced by interactive bash; most tools source it explicitly |
| Windows | — | System Environment Variables | Use `setx` or Settings > System > Environment Variables |

**Common mistakes Secretless auto-fixes:**
- **macOS:** Adding `export` lines to `~/.zshrc` instead of `~/.zshenv`. Secretless copies them to the correct file during `init`.
- **Linux:** Adding exports to `~/.bash_profile` instead of `~/.bashrc`, or placing them after the interactive guard in `.bashrc`. Secretless inserts them before the guard.
- **Windows:** Setting keys only in PowerShell `$PROFILE` (session-only). Secretless runs `setx` to set persistent user environment variables.

```bash
# macOS (zsh) — add to ~/.zshenv
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-proj-..."

# Linux (bash) — add to ~/.bashrc (before the interactive guard)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-proj-..."
```

```powershell
# Windows — use setx (or Settings > System > Environment Variables)
setx ANTHROPIC_API_KEY "sk-ant-..."
setx OPENAI_API_KEY "sk-proj-..."
```

**Step 2: Remove keys from AI config files**

Delete any hardcoded keys from `CLAUDE.md`, `.cursorrules`, `.env`, etc.

**Step 3: Run secretless init**

```bash
npx secretless-ai init
```

Secretless detects which env vars are set and adds a reference table to your AI tool's instruction file. The AI knows *which* keys are available and *how* to authenticate — without seeing the actual values.

**Step 4: Verify**

```bash
npx secretless-ai verify
```

```
  Env vars available (usable by tools):
    + ANTHROPIC_API_KEY
    + OPENAI_API_KEY

  AI context files: clean (no credentials found)

  PASS: Secrets are accessible via env vars but hidden from AI context.
```

**Before:** Claude sees `ANTHROPIC_API_KEY=sk-ant-api03-abc123...` in CLAUDE.md — the key is in the context window, extractable via prompt injection.

**After:** Claude sees a table saying `$ANTHROPIC_API_KEY` exists and the auth header is `x-api-key: $ANTHROPIC_API_KEY`. It uses `$ANTHROPIC_API_KEY` in shell commands. The shell resolves it. Claude never sees the actual value.

## Commands

### `npx secretless-ai init`

Detects AI tools in your project and installs protections. If API keys are set as env vars, includes a reference table with service names and auth header formats so the AI can use them without seeing values. Safe to run multiple times.

### `npx secretless-ai scan`

Scans config files for hardcoded credentials — both project-level and global (`~/.claude/CLAUDE.md`). Detects 49 credential patterns including Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe, SendGrid, Supabase, Azure, GitLab, Twilio, Mailgun, and more.

```
  Found 2 credential(s):

  [CRIT] Anthropic API Key
         ~/.claude/CLAUDE.md:286
         ANTHROPIC_API_KEY=[Anthropic API Key REDACTED]

  [CRIT] OpenAI Project Key
         ~/.claude/CLAUDE.md:284
         OPENAI_API_KEY=[OpenAI Project Key REDACTED]
```

### `npx secretless-ai verify`

Confirms keys are usable but hidden from AI. Checks that env vars are set AND that the actual key values don't appear in any AI context file.

```
  PASS: Secrets are accessible via env vars but hidden from AI context.
```

### `npx secretless-ai doctor`

Diagnoses shell profile issues that cause "No API keys found" errors. Detects when keys are in an interactive-only profile (like `~/.zshrc`) that non-interactive subprocesses can't see.

Use `--fix` to auto-fix: copies export lines from the wrong profile to the correct one (non-destructive, does not modify the original file).

```bash
npx secretless-ai doctor         # Diagnose
npx secretless-ai doctor --fix   # Diagnose and auto-fix
```

Note: `init` also runs this auto-fix automatically, so most users never need to run `doctor` separately.

```
  Secretless Doctor

  Platform: darwin
  Shell:    zsh

  Shell profiles:
    - ~/.zshenv (RECOMMENDED): not found
    + ~/.zshrc (interactive-only): 2 key(s)
    - ~/.zprofile (login-only): not found

  Auto-fix applied:
    Copied 2 export(s) from ~/.zshrc to ~/.zshenv
      + ANTHROPIC_API_KEY
      + OPENAI_API_KEY
    Restart your terminal for changes to take effect.
```

### `npx secretless-ai protect-mcp`

Scans all MCP configs on your machine, encrypts plaintext secrets into a local vault, and rewrites configs to use the `secretless-mcp` wrapper. Safe to run multiple times — skips already-protected servers.

### `npx secretless-ai mcp-status`

Shows protection status for every MCP server across all clients. Tells you which servers have exposed secrets and which are protected.

### `npx secretless-ai mcp-unprotect`

Restores all MCP configs to their original state from backups. One command to undo everything.

### `npx secretless-ai status`

Shows current protection status.

```
  Protected:  Yes
  Tools:      Claude Code, Cursor
  Hook:       Installed
  Deny rules: 14
  Secrets:    0 found in config files
```

## What Gets Blocked

### File patterns (20+)

`.env`, `.env.*`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.crt`, `.aws/credentials`, `.ssh/*`, `.docker/config.json`, `.git-credentials`, `.npmrc`, `.pypirc`, `*.tfstate`, `*.tfvars`, `secrets/`, `credentials/`

### Credential patterns (49)

Anthropic API keys, OpenAI keys, AWS access keys, GitHub PATs, Slack tokens, Google API keys, Stripe keys, SendGrid keys, Supabase keys, Azure keys, GitLab tokens, Twilio keys, Mailgun keys, MongoDB URIs, JWTs, and 34 more

### Bash commands

Commands that dump secret files (`cat .env`, `head *.key`) and commands that echo secret environment variables (`echo $API_KEY`, `echo $SECRET`)

## Claude Code Hook

For Claude Code, Secretless installs a PreToolUse hook that intercepts every `Read`, `Grep`, `Glob`, `Bash`, `Write`, and `Edit` tool call. The hook runs *before* the tool executes, so secrets never enter the AI context window.

```bash
# .claude/hooks/secretless-guard.sh
# Runs before every tool call, checks file paths against block list
# Returns deny decision if a secret file is targeted
```

Additionally, Secretless adds `permissions.deny` rules to `.claude/settings.json` as a second layer of defense, and adds instructions to `CLAUDE.md` so Claude understands why certain files are blocked.

## Development

```bash
npm run build      # Compile TypeScript to dist/
npm test           # Run tests (vitest)
npm run dev        # Watch mode — recompile on file changes
npm run clean      # Remove dist/ directory
```

## Requirements

- Node.js 18+
- A project directory with at least one AI tool configured (or Secretless defaults to Claude Code)

## Zero Dependencies

Secretless has zero runtime dependencies. The npm package is 18 KB.

## OpenA2A Ecosystem

| Project | Description | Install |
|---------|-------------|---------|
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Agent Identity Management -- identity and access control for AI agents | `pip install aim-sdk` |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner -- 147 checks, attack mode, auto-fix | `npx hackmyagent secure` |
| [**OASB**](https://github.com/opena2a-org/oasb) | Open Agent Security Benchmark -- 182 attack scenarios | `npm install @opena2a/oasb` |
| [**ARP**](https://github.com/opena2a-org/arp) | Agent Runtime Protection -- process, network, filesystem monitoring | `npm install @opena2a/arp` |
| [**Secretless AI**](https://github.com/opena2a-org/secretless-ai) | Keep credentials out of AI context windows | `npx secretless-ai init` |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Damn Vulnerable AI Agent -- security training and red-teaming | `docker pull opena2a/dvaa` |

## License

Apache-2.0
