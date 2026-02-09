# Secretless

[![npm version](https://img.shields.io/npm/v/secretless.svg)](https://www.npmjs.com/package/secretless)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

One command to keep secrets out of AI. Works with Claude Code, Cursor, Copilot, Windsurf, Cline, and Aider.

```bash
npx secretless init
```

## The Problem

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
npx secretless init
```

Output:

```
  Secretless v0.2.0
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

**Step 1: Move keys to your shell profile**

```bash
# Add to ~/.zshenv (or ~/.bashrc)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-proj-..."
```

**Step 2: Remove keys from AI config files**

Delete any hardcoded keys from `CLAUDE.md`, `.cursorrules`, `.env`, etc.

**Step 3: Run secretless init**

```bash
npx secretless init
```

Secretless detects which env vars are set and adds a reference table to your AI tool's instruction file. The AI knows *which* keys are available and *how* to authenticate — without seeing the actual values.

**Step 4: Verify**

```bash
npx secretless verify
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

### `npx secretless init`

Detects AI tools in your project and installs protections. If API keys are set as env vars, includes a reference table with service names and auth header formats so the AI can use them without seeing values. Safe to run multiple times.

### `npx secretless scan`

Scans config files for hardcoded credentials — both project-level and global (`~/.claude/CLAUDE.md`). Detects 12 credential patterns including Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe, SendGrid, Supabase, and Azure keys.

```
  Found 2 credential(s):

  [CRIT] Anthropic API Key
         ~/.claude/CLAUDE.md:286
         ANTHROPIC_API_KEY=[Anthropic API Key REDACTED]

  [CRIT] OpenAI Project Key
         ~/.claude/CLAUDE.md:284
         OPENAI_API_KEY=[OpenAI Project Key REDACTED]
```

### `npx secretless verify`

Confirms keys are usable but hidden from AI. Checks that env vars are set AND that the actual key values don't appear in any AI context file.

```
  PASS: Secrets are accessible via env vars but hidden from AI context.
```

### `npx secretless status`

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

### Credential patterns (12)

Anthropic API keys, OpenAI keys (project + legacy), AWS access keys, GitHub PATs (classic + fine-grained), Slack tokens, Google API keys, Stripe live keys, SendGrid keys, Supabase service keys, Azure keys

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

## Requirements

- Node.js 18+
- A project directory with at least one AI tool configured (or Secretless defaults to Claude Code)

## Zero Dependencies

Secretless has zero runtime dependencies. The npm package is 18 KB.

## License

Apache-2.0
