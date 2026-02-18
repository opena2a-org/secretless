/**
 * Shell Profile Doctor
 *
 * Diagnoses why API keys set in shell profiles (e.g. .zshrc) aren't available
 * in non-interactive subprocesses like Claude Code's Bash tool, CI/CD, or Docker.
 *
 * Security: NEVER reads or stores actual key values. Only detects
 * `export VAR_NAME=` presence in shell profiles.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CREDENTIAL_PATTERNS } from './patterns';

// ── Types ────────────────────────────────────────────────────────────────────

export interface DoctorOptions {
  homeDir?: string;
  shell?: string;
  platform?: string;
  envOverride?: Record<string, string | undefined>;
}

export type Severity = 'error' | 'warn' | 'info';
export type HealthStatus = 'healthy' | 'degraded' | 'broken';

export interface DoctorFinding {
  severity: Severity;
  message: string;
  fix?: string;
}

export interface ProfileInfo {
  path: string;
  exists: boolean;
  /** Which env var names have `export VAR=` lines (not commented out) */
  exportedVars: string[];
  /** Whether this profile is sourced by non-interactive shells */
  nonInteractive: boolean;
  /** Recommendation label for this profile */
  recommendation: 'recommended' | 'interactive-only' | 'login-only' | 'none';
}

export interface DoctorResult {
  platform: string;
  shell: string;
  profiles: ProfileInfo[];
  findings: DoctorFinding[];
  health: HealthStatus;
}

export interface QuickDiagnosisResult {
  /** Env var names found in interactive-only profiles but missing from process.env */
  wrongProfile: string[];
  /** Env var names not found in any profile */
  missingEverywhere: string[];
}

// ── Shell profile knowledge ──────────────────────────────────────────────────

interface ProfileSpec {
  /** Relative to home directory */
  file: string;
  nonInteractive: boolean;
  recommendation: 'recommended' | 'interactive-only' | 'login-only' | 'none';
}

const ZSH_PROFILES: ProfileSpec[] = [
  { file: '.zshenv', nonInteractive: true, recommendation: 'recommended' },
  { file: '.zshrc', nonInteractive: false, recommendation: 'interactive-only' },
  { file: '.zprofile', nonInteractive: false, recommendation: 'login-only' },
];

const BASH_PROFILES: ProfileSpec[] = [
  { file: '.bashrc', nonInteractive: false, recommendation: 'recommended' },
  { file: '.bash_profile', nonInteractive: false, recommendation: 'login-only' },
  { file: '.profile', nonInteractive: false, recommendation: 'login-only' },
];

// ── Known env var names to look for ──────────────────────────────────────────

function getKnownEnvVarNames(): string[] {
  const names = new Set<string>();
  for (const p of CREDENTIAL_PATTERNS) {
    names.add(p.envPrefix);
  }
  return [...names];
}

// ── Profile scanning ─────────────────────────────────────────────────────────

const EXPORT_LINE_RE = /^\s*export\s+([A-Z_][A-Z0-9_]*)=/;
const COMMENT_RE = /^\s*#/;

function scanProfile(filePath: string, knownVars: string[]): string[] {
  if (!fs.existsSync(filePath)) return [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const found: string[] = [];
  for (const line of content.split('\n')) {
    if (COMMENT_RE.test(line)) continue;
    const match = EXPORT_LINE_RE.exec(line);
    if (match && knownVars.includes(match[1])) {
      found.push(match[1]);
    }
  }
  return found;
}

// ── Main doctor function ─────────────────────────────────────────────────────

export function doctor(options?: DoctorOptions): DoctorResult {
  const home = options?.homeDir ?? os.homedir();
  const shell = options?.shell ?? process.env.SHELL ?? '';
  const platform = options?.platform ?? os.platform();
  const env = options?.envOverride ?? process.env;
  const knownVars = getKnownEnvVarNames();

  // Pick profile specs based on shell
  const shellName = path.basename(shell);
  let specs: ProfileSpec[];
  if (shellName === 'zsh' || shell.endsWith('/zsh')) {
    specs = ZSH_PROFILES;
  } else if (shellName === 'bash' || shell.endsWith('/bash')) {
    specs = BASH_PROFILES;
  } else {
    // Default to zsh on macOS, bash elsewhere
    specs = platform === 'darwin' ? ZSH_PROFILES : BASH_PROFILES;
  }

  // Scan each profile
  const profiles: ProfileInfo[] = specs.map((spec) => {
    const fullPath = path.join(home, spec.file);
    const exists = fs.existsSync(fullPath);
    const exportedVars = exists ? scanProfile(fullPath, knownVars) : [];
    return {
      path: fullPath,
      exists,
      exportedVars,
      nonInteractive: spec.nonInteractive,
      recommendation: spec.recommendation,
    };
  });

  // Build findings
  const findings: DoctorFinding[] = [];

  // Check each known env var
  const varsInEnv = knownVars.filter((v) => !!env[v]);
  const varsNotInEnv = knownVars.filter((v) => !env[v]);

  // Vars in a non-recommended profile but not in env
  const allExportedVars = new Set<string>();
  const varsInNonInteractiveProfile = new Set<string>();
  const varsInInteractiveOnlyProfile = new Set<string>();

  for (const profile of profiles) {
    for (const v of profile.exportedVars) {
      allExportedVars.add(v);
      if (profile.nonInteractive) {
        varsInNonInteractiveProfile.add(v);
      } else {
        varsInInteractiveOnlyProfile.add(v);
      }
    }
  }

  // Find keys in wrong profile: exported in interactive-only but NOT in env
  // and NOT also in a non-interactive profile
  for (const v of varsInInteractiveOnlyProfile) {
    if (!varsInNonInteractiveProfile.has(v) && !env[v]) {
      const interactiveProfile = profiles.find(
        (p) => !p.nonInteractive && p.exportedVars.includes(v),
      );
      const recommendedProfile = profiles.find((p) => p.recommendation === 'recommended');

      if (interactiveProfile && recommendedProfile) {
        findings.push({
          severity: 'error',
          message: `${v} is in ~/${path.basename(interactiveProfile.path)} (interactive-only) but not available in subprocesses`,
          fix: `Move the export line from ~/${path.basename(interactiveProfile.path)} to ~/${path.basename(recommendedProfile.path)}`,
        });
      }
    }
  }

  // Vars in env and in non-interactive profile = healthy
  for (const v of varsInEnv) {
    if (varsInNonInteractiveProfile.has(v)) {
      findings.push({
        severity: 'info',
        message: `${v} is correctly configured and available`,
      });
    } else if (varsInInteractiveOnlyProfile.has(v)) {
      // In env (because we're in an interactive shell) but in wrong profile
      const recommendedProfile = profiles.find((p) => p.recommendation === 'recommended');
      if (recommendedProfile) {
        findings.push({
          severity: 'warn',
          message: `${v} works in your terminal but may fail in subprocesses (CI, Docker, Claude Code Bash)`,
          fix: `Move the export line to ~/${path.basename(recommendedProfile.path)}`,
        });
      }
    }
  }

  // Vars not in env and not in any profile
  const varsNowhereButExpected = varsNotInEnv.filter((v) => !allExportedVars.has(v));
  // Only report missing vars that users commonly set (skip the 49-pattern exhaustive list)
  // We don't report all missing vars — that'd be noise. Only if they're in a profile but not in env.

  // Determine health
  let health: HealthStatus = 'healthy';
  if (findings.some((f) => f.severity === 'error')) {
    health = 'broken';
  } else if (findings.some((f) => f.severity === 'warn')) {
    health = 'degraded';
  } else if (varsInEnv.length === 0 && allExportedVars.size === 0) {
    health = 'broken';
    findings.push({
      severity: 'error',
      message: 'No API keys found in env vars or shell profiles',
      fix: `Add export lines to ~/${path.basename(profiles.find((p) => p.recommendation === 'recommended')?.path ?? specs[0].file)}`,
    });
  }

  return {
    platform,
    shell: shellName || 'unknown',
    profiles,
    findings,
    health,
  };
}

// ── Quick diagnosis (lightweight, for verify output) ─────────────────────────

export function quickDiagnosis(options?: DoctorOptions): QuickDiagnosisResult {
  const home = options?.homeDir ?? os.homedir();
  const shell = options?.shell ?? process.env.SHELL ?? '';
  const platform = options?.platform ?? os.platform();
  const env = options?.envOverride ?? process.env;
  const knownVars = getKnownEnvVarNames();

  // Only check the 2-3 most common profiles
  const shellName = path.basename(shell);
  let quickProfiles: ProfileSpec[];
  if (shellName === 'zsh' || shell.endsWith('/zsh') || platform === 'darwin') {
    quickProfiles = [
      { file: '.zshenv', nonInteractive: true, recommendation: 'recommended' },
      { file: '.zshrc', nonInteractive: false, recommendation: 'interactive-only' },
    ];
  } else {
    quickProfiles = [
      { file: '.bashrc', nonInteractive: false, recommendation: 'recommended' },
      { file: '.bash_profile', nonInteractive: false, recommendation: 'login-only' },
    ];
  }

  const wrongProfile: string[] = [];
  const allFound = new Set<string>();

  for (const spec of quickProfiles) {
    const fullPath = path.join(home, spec.file);
    const exported = scanProfile(fullPath, knownVars);
    for (const v of exported) {
      allFound.add(v);
      // In an interactive-only profile and not in env = wrong profile
      if (!spec.nonInteractive && !env[v]) {
        wrongProfile.push(v);
      }
    }
  }

  // Vars not found in any checked profile and not in env
  const missingEverywhere = knownVars.filter((v) => !allFound.has(v) && !env[v]);

  return { wrongProfile, missingEverywhere };
}
