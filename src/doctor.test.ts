import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { doctor, quickDiagnosis, fixProfiles } from './doctor';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-ai-doctor-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('doctor', () => {
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('detects healthy state: key in .zshenv and in process.env', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\nexport OPENAI_API_KEY="sk-proj-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {
        ANTHROPIC_API_KEY: 'set',
        OPENAI_API_KEY: 'set',
      },
    });

    expect(result.health).toBe('healthy');
    expect(result.shell).toBe('zsh');
    expect(result.platform).toBe('darwin');

    const infoFindings = result.findings.filter((f) => f.severity === 'info');
    expect(infoFindings.length).toBe(2);
    expect(infoFindings[0].message).toContain('correctly configured');
  });

  it('detects wrong profile: key in .zshrc only, not in process.env', () => {
    // .zshrc is interactive-only, so non-interactive shells won't source it
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.health).toBe('broken');
    const errorFindings = result.findings.filter((f) => f.severity === 'error');
    expect(errorFindings.length).toBeGreaterThanOrEqual(1);

    const wrongProfileFinding = errorFindings.find((f) =>
      f.message.includes('ANTHROPIC_API_KEY') && f.message.includes('interactive-only'),
    );
    expect(wrongProfileFinding).toBeDefined();
    expect(wrongProfileFinding!.fix).toContain('.zshenv');
  });

  it('detects no keys anywhere', () => {
    // No profile files, no env vars
    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.health).toBe('broken');
    const errorFindings = result.findings.filter((f) => f.severity === 'error');
    expect(errorFindings.some((f) => f.message.includes('No API keys found'))).toBe(true);
  });

  it('handles missing profile files gracefully', () => {
    // home dir exists but no profile files — should not throw
    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.profiles.every((p) => !p.exists)).toBe(true);
    expect(result.profiles.every((p) => p.exportedVars.length === 0)).toBe(true);
  });

  it('detects bash on Linux', () => {
    fs.writeFileSync(
      path.join(home, '.bashrc'),
      'export AWS_ACCESS_KEY_ID="AKIA..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
      envOverride: {},
    });

    expect(result.shell).toBe('bash');
    expect(result.platform).toBe('linux');

    // .bashrc profiles should be checked
    const bashrcProfile = result.profiles.find((p) => p.path.endsWith('.bashrc'));
    expect(bashrcProfile).toBeDefined();
    expect(bashrcProfile!.exportedVars).toContain('AWS_ACCESS_KEY_ID');
  });

  it('ignores commented-out exports', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      '# export ANTHROPIC_API_KEY="sk-ant-..."\nexport OPENAI_API_KEY="sk-proj-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { OPENAI_API_KEY: 'set' },
    });

    const zshenvProfile = result.profiles.find((p) => p.path.endsWith('.zshenv'));
    expect(zshenvProfile).toBeDefined();
    // Commented line should be ignored
    expect(zshenvProfile!.exportedVars).not.toContain('ANTHROPIC_API_KEY');
    // Uncommented line should be found
    expect(zshenvProfile!.exportedVars).toContain('OPENAI_API_KEY');
  });

  it('warns when key is in env but only in interactive profile', () => {
    // Key is in .zshrc and happens to be in env (because we're in an interactive shell)
    // but it won't work in non-interactive subprocesses
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.health).toBe('degraded');
    const warnFindings = result.findings.filter((f) => f.severity === 'warn');
    expect(warnFindings.length).toBeGreaterThanOrEqual(1);
    expect(warnFindings[0].message).toContain('may fail in subprocesses');
  });

  it('reports all zsh profiles with correct metadata', () => {
    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.profiles.length).toBe(3);

    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'));
    expect(zshenv!.nonInteractive).toBe(true);
    expect(zshenv!.recommendation).toBe('recommended');

    const zshrc = result.profiles.find((p) => p.path.endsWith('.zshrc'));
    expect(zshrc!.nonInteractive).toBe(false);
    expect(zshrc!.recommendation).toBe('interactive-only');

    const zprofile = result.profiles.find((p) => p.path.endsWith('.zprofile'));
    expect(zprofile!.nonInteractive).toBe(false);
    expect(zprofile!.recommendation).toBe('login-only');
  });

  it('defaults to zsh on macOS when shell is unknown', () => {
    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'darwin',
      envOverride: {},
    });

    // Should check zsh profiles since platform is darwin
    expect(result.profiles.some((p) => p.path.endsWith('.zshenv'))).toBe(true);
  });

  it('defaults to bash on linux when shell is unknown', () => {
    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'linux',
      envOverride: {},
    });

    // Should check bash profiles since platform is linux
    expect(result.profiles.some((p) => p.path.endsWith('.bashrc'))).toBe(true);
  });
});

describe('quickDiagnosis', () => {
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('finds keys in wrong profile', () => {
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\nexport OPENAI_API_KEY="sk-proj-..."\n',
    );

    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.wrongProfile).toContain('ANTHROPIC_API_KEY');
    expect(result.wrongProfile).toContain('OPENAI_API_KEY');
  });

  it('returns empty when keys are correctly in .zshenv', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\n',
    );

    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.wrongProfile).toEqual([]);
  });

  it('reports vars missing everywhere', () => {
    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    // All known vars should be reported as missing everywhere
    expect(result.missingEverywhere.length).toBeGreaterThan(0);
    expect(result.missingEverywhere).toContain('ANTHROPIC_API_KEY');
  });

  it('works with bash profiles', () => {
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export GITHUB_TOKEN="ghp_..."\n',
    );

    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
      envOverride: {},
    });

    // .bash_profile is login-only, key not in env
    expect(result.wrongProfile).toContain('GITHUB_TOKEN');
  });
});

describe('fixProfiles', () => {
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('copies exports from .zshrc to .zshenv', () => {
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      '# my config\nexport ANTHROPIC_API_KEY="sk-ant-test123"\nexport OPENAI_API_KEY="sk-proj-test456"\naliases...\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('ANTHROPIC_API_KEY');
    expect(result!.fixed).toContain('OPENAI_API_KEY');
    expect(result!.sourceProfile).toBe('.zshrc');
    expect(result!.targetProfile).toBe('.zshenv');
    expect(result!.created).toBe(true);

    // Verify .zshenv was created with the export lines
    const zshenv = fs.readFileSync(path.join(home, '.zshenv'), 'utf-8');
    expect(zshenv).toContain('export ANTHROPIC_API_KEY="sk-ant-test123"');
    expect(zshenv).toContain('export OPENAI_API_KEY="sk-proj-test456"');
    expect(zshenv).toContain('# Added by secretless-ai');
  });

  it('appends to existing .zshenv without overwriting', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      '# existing content\nexport PATH="/usr/local/bin:$PATH"\n',
    );
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-test123"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).not.toBeNull();
    expect(result!.created).toBe(false);

    const zshenv = fs.readFileSync(path.join(home, '.zshenv'), 'utf-8');
    // Original content preserved
    expect(zshenv).toContain('export PATH="/usr/local/bin:$PATH"');
    // New export added
    expect(zshenv).toContain('export ANTHROPIC_API_KEY="sk-ant-test123"');
  });

  it('returns null when nothing needs fixing', () => {
    // Key already in the correct profile
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-test123"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).toBeNull();
  });

  it('skips vars already in .zshenv', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-already-here"\n',
    );
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-also-here"\nexport OPENAI_API_KEY="sk-proj-only-here"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).not.toBeNull();
    // ANTHROPIC already in .zshenv, should not be copied again
    expect(result!.fixed).not.toContain('ANTHROPIC_API_KEY');
    // OPENAI only in .zshrc, should be copied
    expect(result!.fixed).toContain('OPENAI_API_KEY');
  });

  it('copies exports from .bash_profile to .bashrc on Linux', () => {
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export GITHUB_TOKEN="ghp_abcdef1234567890abcdef1234567890abcd"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('GITHUB_TOKEN');
    expect(result!.sourceProfile).toBe('.bash_profile');
    expect(result!.targetProfile).toBe('.bashrc');

    const bashrc = fs.readFileSync(path.join(home, '.bashrc'), 'utf-8');
    expect(bashrc).toContain('export GITHUB_TOKEN=');
  });

  it('returns null when no profiles exist', () => {
    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).toBeNull();
  });

  it('does not modify the source profile', () => {
    const originalContent = '# my zshrc\nexport ANTHROPIC_API_KEY="sk-ant-test123"\nsome other stuff\n';
    fs.writeFileSync(path.join(home, '.zshrc'), originalContent);

    fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    // Source file should be untouched
    const afterContent = fs.readFileSync(path.join(home, '.zshrc'), 'utf-8');
    expect(afterContent).toBe(originalContent);
  });
});
