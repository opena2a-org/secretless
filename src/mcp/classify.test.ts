import { describe, it, expect } from 'vitest';
import { classifyEnvVars, ClassifiedEnv } from './classify';

describe('classifyEnvVars', () => {
  it('classifies known secret key names as secrets', () => {
    const env = {
      GITHUB_TOKEN: 'ghp_abc123',
      OPENAI_API_KEY: 'sk-proj-abc',
      ANTHROPIC_API_KEY: 'sk-ant-abc',
      SLACK_BOT_TOKEN: 'xoxb-token',
      DATABASE_URL: 'postgres://user:pass@host/db',
      MONGODB_URI: 'mongodb+srv://user:pass@cluster',
      REDIS_URL: 'redis://localhost:6379',
      AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
      AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      AWS_SESSION_TOKEN: 'FwoGZXIvYXdzEBY...',
      STRIPE_SECRET_KEY: 'sk_test_abc123',
      SENDGRID_API_KEY: 'SG.abc123',
      PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----',
      CLIENT_SECRET: 'my-client-secret',
      SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T00/B00/xxx',
    };

    const result = classifyEnvVars(env);

    for (const key of Object.keys(env)) {
      expect(result.secrets).toHaveProperty(key);
      expect(result.nonSecrets).not.toHaveProperty(key);
    }
  });

  it('classifies known non-secret key names as non-secrets', () => {
    const env = {
      NODE_ENV: 'production',
      LOG_LEVEL: 'info',
      DEBUG: 'false',
      LANG: 'en_US.UTF-8',
      TZ: 'UTC',
      HOME: '/home/user',
    };

    const result = classifyEnvVars(env);

    for (const key of Object.keys(env)) {
      expect(result.nonSecrets).toHaveProperty(key);
      expect(result.secrets).not.toHaveProperty(key);
    }
  });

  it('classifies *_TOKEN suffix as secret', () => {
    const result = classifyEnvVars({
      CUSTOM_SERVICE_TOKEN: 'some-token-value',
      MY_APP_TOKEN: 'another-token',
    });

    expect(result.secrets).toHaveProperty('CUSTOM_SERVICE_TOKEN');
    expect(result.secrets).toHaveProperty('MY_APP_TOKEN');
    expect(Object.keys(result.nonSecrets)).toHaveLength(0);
  });

  it('classifies *_KEY suffix as secret', () => {
    const result = classifyEnvVars({
      ENCRYPTION_KEY: 'abc123def456',
      SIGNING_KEY: 'my-signing-key',
    });

    expect(result.secrets).toHaveProperty('ENCRYPTION_KEY');
    expect(result.secrets).toHaveProperty('SIGNING_KEY');
  });

  it('classifies *_SECRET suffix as secret', () => {
    const result = classifyEnvVars({
      APP_SECRET: 'super-secret',
      JWT_SECRET: 'jwt-secret-value',
    });

    expect(result.secrets).toHaveProperty('APP_SECRET');
    expect(result.secrets).toHaveProperty('JWT_SECRET');
  });

  it('classifies *_PASSWORD suffix as secret', () => {
    const result = classifyEnvVars({
      DB_PASSWORD: 'hunter2',
      ADMIN_PASSWORD: 'admin-pass',
    });

    expect(result.secrets).toHaveProperty('DB_PASSWORD');
    expect(result.secrets).toHaveProperty('ADMIN_PASSWORD');
  });

  it('classifies DATABASE_URL with embedded password as secret', () => {
    const result = classifyEnvVars({
      DATABASE_URL: 'postgres://user:secretpass@db.host.com:5432/mydb',
    });

    // DATABASE_URL is an exact-match secret, but also test a generic URL key
    expect(result.secrets).toHaveProperty('DATABASE_URL');
  });

  it('classifies URI suffix with embedded password as secret', () => {
    const result = classifyEnvVars({
      CUSTOM_URL: 'postgres://admin:p4ssw0rd@db.example.com:5432/app',
      SERVICE_URI: 'mongodb://root:secret123@mongo.host:27017/db',
    });

    expect(result.secrets).toHaveProperty('CUSTOM_URL');
    expect(result.secrets).toHaveProperty('SERVICE_URI');
  });

  it('classifies by value pattern matching (generic key but secret value)', () => {
    const result = classifyEnvVars({
      MY_SETTING: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
      SOME_CONFIG: 'sk-ant-api03-aaaabbbbccccddddeeeeffffgggg',
      RANDOM_VAR: 'glpat-xxxxxxxxxxxxxxxxxxxx',
    });

    expect(result.secrets).toHaveProperty('MY_SETTING');
    expect(result.secrets).toHaveProperty('SOME_CONFIG');
    expect(result.secrets).toHaveProperty('RANDOM_VAR');
  });

  it('classifies non-secret URLs, hosts, and ports as non-secrets', () => {
    const result = classifyEnvVars({
      API_URL: 'https://api.example.com',
      SERVICE_HOST: 'localhost',
      DB_PORT: '5432',
      AWS_REGION: 'us-east-1',
      APP_ENDPOINT: 'https://app.example.com/v1',
      NOTIFY_EMAIL: 'admin@example.com',
      APP_NAME: 'my-service',
      WORKER_ID: 'worker-1',
      APP_VERSION: '2.1.0',
      RUN_MODE: 'production',
      OUTPUT_FORMAT: 'json',
      REQUEST_TIMEOUT: '30000',
      SLACK_CHANNEL: '#general',
      CACHE_DIR: '/tmp/cache',
      DATA_PATH: '/var/data',
    });

    for (const key of Object.keys(result.nonSecrets)) {
      expect(result.secrets).not.toHaveProperty(key);
    }
    expect(result.nonSecrets).toHaveProperty('API_URL');
    expect(result.nonSecrets).toHaveProperty('SERVICE_HOST');
    expect(result.nonSecrets).toHaveProperty('DB_PORT');
    expect(result.nonSecrets).toHaveProperty('AWS_REGION');
    expect(result.nonSecrets).toHaveProperty('APP_ENDPOINT');
    expect(result.nonSecrets).toHaveProperty('NOTIFY_EMAIL');
    expect(result.nonSecrets).toHaveProperty('APP_NAME');
    expect(result.nonSecrets).toHaveProperty('WORKER_ID');
    expect(result.nonSecrets).toHaveProperty('APP_VERSION');
    expect(result.nonSecrets).toHaveProperty('RUN_MODE');
    expect(result.nonSecrets).toHaveProperty('OUTPUT_FORMAT');
    expect(result.nonSecrets).toHaveProperty('REQUEST_TIMEOUT');
    expect(result.nonSecrets).toHaveProperty('SLACK_CHANNEL');
    expect(result.nonSecrets).toHaveProperty('CACHE_DIR');
    expect(result.nonSecrets).toHaveProperty('DATA_PATH');
  });

  it('handles empty env object', () => {
    const result = classifyEnvVars({});

    expect(result.secrets).toEqual({});
    expect(result.nonSecrets).toEqual({});
  });

  it('handles env with only secrets', () => {
    const result = classifyEnvVars({
      GITHUB_TOKEN: 'ghp_abc',
      API_KEY: 'some-key',
      DB_PASSWORD: 'pass',
    });

    expect(Object.keys(result.secrets)).toHaveLength(3);
    expect(Object.keys(result.nonSecrets)).toHaveLength(0);
  });

  it('handles env with only non-secrets', () => {
    const result = classifyEnvVars({
      NODE_ENV: 'development',
      LOG_LEVEL: 'debug',
      HOME: '/Users/test',
    });

    expect(Object.keys(result.nonSecrets)).toHaveLength(3);
    expect(Object.keys(result.secrets)).toHaveLength(0);
  });

  it('classifies remaining secret suffixes (_CREDENTIAL, _API_KEY, _ACCESS_KEY, _SECRET_KEY, _AUTH, _APIKEY)', () => {
    const result = classifyEnvVars({
      OAUTH_CREDENTIAL: 'cred-value',
      MAPS_API_KEY: 'maps-key',
      S3_ACCESS_KEY: 'access-key',
      HMAC_SECRET_KEY: 'secret-key',
      PROXY_AUTH: 'auth-value',
      SERVICE_APIKEY: 'apikey-value',
    });

    for (const key of Object.keys(result.secrets)) {
      expect(result.nonSecrets).not.toHaveProperty(key);
    }
    expect(result.secrets).toHaveProperty('OAUTH_CREDENTIAL');
    expect(result.secrets).toHaveProperty('MAPS_API_KEY');
    expect(result.secrets).toHaveProperty('S3_ACCESS_KEY');
    expect(result.secrets).toHaveProperty('HMAC_SECRET_KEY');
    expect(result.secrets).toHaveProperty('PROXY_AUTH');
    expect(result.secrets).toHaveProperty('SERVICE_APIKEY');
  });

  it('defaults unknown keys with non-matching values to non-secret', () => {
    const result = classifyEnvVars({
      CUSTOM_SETTING: 'some-plain-value',
      MY_CONFIG: '42',
      FEATURE_FLAG: 'true',
    });

    expect(result.nonSecrets).toHaveProperty('CUSTOM_SETTING');
    expect(result.nonSecrets).toHaveProperty('MY_CONFIG');
    expect(result.nonSecrets).toHaveProperty('FEATURE_FLAG');
    expect(Object.keys(result.secrets)).toHaveLength(0);
  });

  it('value pattern matching detects AWS access keys', () => {
    const result = classifyEnvVars({
      SOME_GENERIC_VAR: 'AKIAIOSFODNN7EXAMPLE',
    });

    expect(result.secrets).toHaveProperty('SOME_GENERIC_VAR');
  });

  it('non-secret ENV suffix is classified correctly', () => {
    const result = classifyEnvVars({
      APP_ENV: 'staging',
      RUNTIME_LEVEL: 'warn',
    });

    expect(result.nonSecrets).toHaveProperty('APP_ENV');
    expect(result.nonSecrets).toHaveProperty('RUNTIME_LEVEL');
  });
});
