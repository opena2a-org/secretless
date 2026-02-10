#!/usr/bin/env node

/**
 * Secretless CLI
 *
 * Usage:
 *   npx secretless-ai init     — Set up protections for detected AI tools
 *   npx secretless-ai scan     — Scan for hardcoded secrets
 *   npx secretless-ai status   — Show current protection status
 */

import * as path from 'path';
import { init } from './init';
import { scan } from './scan';
import { status } from './status';
import { verify } from './verify';
import { toolDisplayName } from './detect';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version: VERSION } = require('../package.json');

function main(): void {
  const args = process.argv.slice(2);
  const command = args[0];
  const dirArg = args[1];
  const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();

  switch (command) {
    case 'init':
      runInit(projectDir);
      break;
    case 'scan':
      runScan(projectDir);
      break;
    case 'status':
      runStatus(projectDir);
      break;
    case 'verify':
      runVerify(projectDir);
      break;
    case '--version':
    case '-v':
      console.log(`secretless v${VERSION}`);
      break;
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

function runInit(projectDir: string): void {
  console.log('\n  Secretless v' + VERSION);
  console.log('  Keeping secrets out of AI\n');

  const result = init(projectDir);

  // Report detected tools
  if (result.toolsDetected.length > 0) {
    console.log('  Detected:');
    for (const tool of result.toolsDetected) {
      console.log(`    + ${toolDisplayName(tool)}`);
    }
  } else {
    console.log('  No AI tools detected, defaulting to Claude Code');
  }
  console.log();

  // Report configured tools
  console.log('  Configured:');
  for (const tool of result.toolsConfigured) {
    console.log(`    * ${toolDisplayName(tool)}`);
  }
  console.log();

  // Report files
  if (result.filesCreated.length > 0) {
    console.log('  Created:');
    for (const f of result.filesCreated) {
      console.log(`    + ${f}`);
    }
    console.log();
  }

  if (result.filesModified.length > 0) {
    console.log('  Modified:');
    for (const f of result.filesModified) {
      console.log(`    ~ ${f}`);
    }
    console.log();
  }

  // Report secrets found
  if (result.secretsFound > 0) {
    console.log(`  Warning: found ${result.secretsFound} hardcoded credential(s)`);
    console.log('  Run `npx secretless-ai scan` to see details\n');
  }

  console.log('  Done. Secrets are now blocked from AI context.\n');
}

function runScan(projectDir: string): void {
  console.log('\n  Secretless Scanner\n');

  const findings = scan(projectDir);

  if (findings.length === 0) {
    console.log('  No hardcoded credentials found.\n');
    return;
  }

  console.log(`  Found ${findings.length} credential(s):\n`);
  for (const finding of findings) {
    const severity = finding.severity === 'critical' ? 'CRIT' : 'HIGH';
    console.log(`  [${severity}] ${finding.patternName}`);
    console.log(`         ${finding.file}:${finding.line}`);
    console.log(`         ${finding.preview}`);
    console.log();
  }

  console.log(`  Run \`npx secretless-ai init\` to add protections.\n`);
  process.exit(findings.length > 0 ? 1 : 0);
}

function runStatus(projectDir: string): void {
  console.log('\n  Secretless Status\n');

  const s = status(projectDir);

  console.log(`  Protected:  ${s.isProtected ? 'Yes' : 'No'}`);
  console.log(`  Tools:      ${s.configuredTools.map(toolDisplayName).join(', ') || 'None'}`);
  console.log(`  Hook:       ${s.hookInstalled ? 'Installed' : 'Not installed'}`);
  console.log(`  Deny rules: ${s.denyRuleCount}`);
  console.log(`  Secrets:    ${s.secretsFound} found in config files`);
  console.log();
}

function runVerify(projectDir: string): void {
  console.log('\n  Secretless Verify\n');

  const result = verify(projectDir);

  // Show env var availability
  const setVars = Object.entries(result.envVars).filter(([, v]) => v);
  const unsetVars = Object.entries(result.envVars).filter(([, v]) => !v);

  if (setVars.length > 0) {
    console.log('  Env vars available (usable by tools):');
    for (const [name] of setVars) {
      console.log(`    + ${name}`);
    }
  }

  if (unsetVars.length > 0) {
    console.log('  Env vars not set:');
    for (const [name] of unsetVars) {
      console.log(`    - ${name}`);
    }
  }
  console.log();

  // Show context exposure
  if (result.exposedInContext.length > 0) {
    console.log('  EXPOSED in AI context (secrets the AI can see):');
    for (const exp of result.exposedInContext) {
      console.log(`    ! ${exp.patternName} in ${exp.file}:${exp.line}`);
    }
    console.log();
  } else {
    console.log('  AI context files: clean (no credentials found)\n');
  }

  // Verdict
  if (result.passed) {
    console.log('  PASS: Secrets are accessible via env vars but hidden from AI context.\n');
  } else if (result.exposedInContext.length > 0) {
    console.log('  FAIL: Credentials found in AI context files.');
    console.log('  Run `npx secretless-ai init` to remediate.\n');
    process.exit(1);
  } else {
    console.log('  WARN: No API keys found in env vars.');
    console.log('  Set keys in ~/.zshenv or ~/.bashrc, then restart your terminal.\n');
    process.exit(1);
  }
}

function printHelp(): void {
  console.log(`
  Secretless v${VERSION}
  Keep secrets out of AI context.

  Usage:
    npx secretless-ai init      Set up protections for your AI tools
    npx secretless-ai scan      Scan for hardcoded secrets
    npx secretless-ai status    Show protection status
    npx secretless-ai verify    Verify keys are usable but hidden from AI

  Options:
    -v, --version    Show version
    -h, --help       Show this help

  Supports: Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Aider

  https://opena2a.org/secretless-ai
`);
}

main();
