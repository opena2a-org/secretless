import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { isWatchRunning, stopWatch, PID_FILE } from './watch';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');

function ensureDir(): void {
  fs.mkdirSync(SECRETLESS_DIR, { recursive: true });
}

function cleanPid(): void {
  try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
}

describe('watch - PID management', () => {
  beforeEach(() => { ensureDir(); cleanPid(); });
  afterEach(() => { cleanPid(); });

  it('isWatchRunning returns false when no PID file exists', () => {
    expect(isWatchRunning()).toBe(false);
  });

  it('isWatchRunning returns false when PID file contains dead process', () => {
    // PID 99999999 almost certainly doesn't exist
    fs.writeFileSync(PID_FILE, '99999999');
    expect(isWatchRunning()).toBe(false);
  });

  it('isWatchRunning returns true for current process PID', () => {
    fs.writeFileSync(PID_FILE, String(process.pid));
    expect(isWatchRunning()).toBe(true);
  });

  it('stopWatch returns false when no PID file exists', () => {
    expect(stopWatch()).toBe(false);
  });
});
