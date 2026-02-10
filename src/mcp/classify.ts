import { CREDENTIAL_PATTERNS } from '../patterns';

export interface ClassifiedEnv {
  secrets: Record<string, string>;
  nonSecrets: Record<string, string>;
}

/** Exact key names that are always secrets. */
const KNOWN_SECRET_KEYS = new Set([
  'GITHUB_TOKEN',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'SLACK_BOT_TOKEN',
  'DATABASE_URL',
  'MONGODB_URI',
  'REDIS_URL',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'STRIPE_SECRET_KEY',
  'SENDGRID_API_KEY',
  'PRIVATE_KEY',
  'CLIENT_SECRET',
  'SLACK_WEBHOOK_URL',
]);

/** Exact key names that are always non-secrets. */
const KNOWN_NON_SECRET_KEYS = new Set([
  'NODE_ENV',
  'LOG_LEVEL',
  'DEBUG',
  'LANG',
  'TZ',
  'HOME',
]);

/** Suffixes that indicate a secret key. */
const SECRET_SUFFIXES = [
  '_TOKEN',
  '_KEY',
  '_SECRET',
  '_PASSWORD',
  '_CREDENTIAL',
  '_API_KEY',
  '_ACCESS_KEY',
  '_SECRET_KEY',
  '_AUTH',
  '_APIKEY',
];

/** Suffixes that indicate a non-secret key (unless the value contains embedded credentials). */
const NON_SECRET_SUFFIXES = [
  '_URL',
  '_URI',
  '_HOST',
  '_PORT',
  '_REGION',
  '_ENDPOINT',
  '_EMAIL',
  '_NAME',
  '_ID',
  '_VERSION',
  '_ENV',
  '_MODE',
  '_LEVEL',
  '_DIR',
  '_PATH',
  '_FORMAT',
  '_TIMEOUT',
  '_CHANNEL',
];

/** Matches a URI scheme with embedded username:password before the @ sign. */
const URI_WITH_PASSWORD_RE = /^[a-z][a-z0-9+.-]*:\/\/[^:]+:[^@]+@/i;
/** Max env var value length to test against URI regex (prevents ReDoS). */
const MAX_URI_CHECK_LEN = 4096;

/**
 * Check whether a value matches any of the 49 credential patterns
 * from the shared patterns module.
 */
function valueMatchesCredentialPattern(value: string): boolean {
  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.regex.test(value)) {
      return true;
    }
  }
  return false;
}

/**
 * Check whether a key ends with any of the given suffixes (case-insensitive).
 */
function hasSuffix(key: string, suffixes: string[]): boolean {
  const upper = key.toUpperCase();
  return suffixes.some(suffix => upper.endsWith(suffix));
}

/**
 * Classify environment variables into secrets and non-secrets.
 *
 * Priority order:
 * 1. Exact key name match -> secret
 * 2. Non-secret exact match -> non-secret
 * 3. Secret suffix match -> secret
 * 4. Value matches credential pattern -> secret
 * 5. Non-secret suffix (but URI with embedded password -> secret)
 * 6. Default -> non-secret
 */
export function classifyEnvVars(env: Record<string, string>): ClassifiedEnv {
  const secrets: Record<string, string> = {};
  const nonSecrets: Record<string, string> = {};

  for (const [key, value] of Object.entries(env)) {
    // 1. Exact key name -> secret
    if (KNOWN_SECRET_KEYS.has(key)) {
      secrets[key] = value;
      continue;
    }

    // 2. Exact key name -> non-secret
    if (KNOWN_NON_SECRET_KEYS.has(key)) {
      nonSecrets[key] = value;
      continue;
    }

    // 3. Secret suffix -> secret
    if (hasSuffix(key, SECRET_SUFFIXES)) {
      secrets[key] = value;
      continue;
    }

    // 4. Value matches credential pattern -> secret
    if (valueMatchesCredentialPattern(value)) {
      secrets[key] = value;
      continue;
    }

    // 5. Non-secret suffix (but URI with embedded password -> secret)
    if (hasSuffix(key, NON_SECRET_SUFFIXES)) {
      if (value.length <= MAX_URI_CHECK_LEN && URI_WITH_PASSWORD_RE.test(value)) {
        secrets[key] = value;
      } else {
        nonSecrets[key] = value;
      }
      continue;
    }

    // 6. Default -> non-secret
    nonSecrets[key] = value;
  }

  return { secrets, nonSecrets };
}
