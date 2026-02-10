/**
 * File watcher daemon for real-time transcript protection.
 * Monitors ~/.claude/projects/ for new/modified .jsonl files and auto-redacts.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { scanTranscriptFile, atomicWrite } from './transcript';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
const PID_FILE = path.join(SECRETLESS_DIR, 'watch.pid');
const LOG_FILE = path.join(SECRETLESS_DIR, 'watch.log');
const TRANSCRIPT_DIR = path.join(os.homedir(), '.claude', 'projects');

/** Debounce window in milliseconds */
const DEBOUNCE_MS = 3000;

/** Plist identifier for macOS LaunchAgent */
const LAUNCH_AGENT_LABEL = 'ai.secretless.watch';

/**
 * Start watching Claude Code transcripts for credentials.
 * Runs in the foreground, monitoring file changes and auto-redacting.
 */
export function startWatch(options?: { logFile?: string }): void {
  const logPath = options?.logFile || LOG_FILE;

  // Ensure directories exist
  fs.mkdirSync(SECRETLESS_DIR, { recursive: true });

  if (!fs.existsSync(TRANSCRIPT_DIR)) {
    log(logPath, 'Transcript directory not found: ' + TRANSCRIPT_DIR);
    log(logPath, 'Start a Claude Code session first, then re-run.');
    return;
  }

  // Write PID file
  fs.writeFileSync(PID_FILE, String(process.pid));
  log(logPath, `Watcher started (PID: ${process.pid})`);
  log(logPath, `Monitoring: ${TRANSCRIPT_DIR}`);

  // Track debounce timers per file
  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

  // Watch for changes
  const watcher = fs.watch(TRANSCRIPT_DIR, { recursive: true }, (eventType, filename) => {
    if (!filename || !filename.endsWith('.jsonl')) return;

    const fullPath = path.join(TRANSCRIPT_DIR, filename);

    // Skip if in tool-results
    if (filename.includes('tool-results')) return;

    // Debounce: Claude Code writes in bursts
    const existing = debounceTimers.get(fullPath);
    if (existing) clearTimeout(existing);

    debounceTimers.set(fullPath, setTimeout(() => {
      debounceTimers.delete(fullPath);
      processFile(fullPath, logPath);
    }, DEBOUNCE_MS));
  });

  // Graceful shutdown
  const shutdown = () => {
    log(logPath, 'Watcher stopping...');
    watcher.close();
    for (const timer of debounceTimers.values()) clearTimeout(timer);
    debounceTimers.clear();
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    log(logPath, 'Watcher stopped.');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

function processFile(filePath: string, logPath: string): void {
  try {
    const { findings, redactedLines } = scanTranscriptFile(filePath, false);
    if (findings.length > 0 && redactedLines) {
      atomicWrite(filePath, redactedLines);
      const displayPath = filePath.replace(os.homedir(), '~');
      log(logPath, `Redacted ${findings.length} credential(s) in ${displayPath}`);
      for (const f of findings) {
        log(logPath, `  ${f.jsonPath} → [REDACTED:${f.patternId}]`);
      }
    }
  } catch (err) {
    log(logPath, `Error processing ${filePath}: ${err}`);
  }
}

function log(logPath: string, message: string): void {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] ${message}\n`;
  try {
    fs.appendFileSync(logPath, line);
  } catch {
    // Fallback to stderr if log file is not writable
  }
  process.stderr.write(line);
}

/**
 * Stop the running watcher process.
 */
export function stopWatch(): boolean {
  if (!fs.existsSync(PID_FILE)) return false;

  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, 'utf-8').trim(), 10);
    process.kill(pid, 'SIGTERM');
    fs.unlinkSync(PID_FILE);
    return true;
  } catch {
    // Process may already be dead
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    return false;
  }
}

/**
 * Check if the watcher is currently running.
 */
export function isWatchRunning(): boolean {
  if (!fs.existsSync(PID_FILE)) return false;

  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, 'utf-8').trim(), 10);
    process.kill(pid, 0); // Signal 0 = check if process exists
    return true;
  } catch {
    return false;
  }
}

/**
 * Install macOS LaunchAgent for auto-start on login.
 */
export function installLaunchAgent(): boolean {
  if (process.platform !== 'darwin') return false;

  const launchAgentsDir = path.join(os.homedir(), 'Library', 'LaunchAgents');
  fs.mkdirSync(launchAgentsDir, { recursive: true });

  const plistPath = path.join(launchAgentsDir, `${LAUNCH_AGENT_LABEL}.plist`);

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>npx</string>
    <string>secretless-ai</string>
    <string>watch</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>${LOG_FILE}</string>
  <key>StandardOutPath</key>
  <string>${LOG_FILE}</string>
</dict>
</plist>`;

  fs.writeFileSync(plistPath, plist);
  return true;
}

/**
 * Uninstall macOS LaunchAgent.
 */
export function uninstallLaunchAgent(): boolean {
  if (process.platform !== 'darwin') return false;

  const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`);
  if (!fs.existsSync(plistPath)) return false;

  try {
    fs.unlinkSync(plistPath);
    return true;
  } catch {
    return false;
  }
}

// Export constants for testing
export { PID_FILE, LOG_FILE, DEBOUNCE_MS };
