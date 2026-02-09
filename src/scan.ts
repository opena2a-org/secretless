/**
 * Scan project files for hardcoded credentials.
 */

import * as fs from 'fs';
import * as path from 'path';
import { CREDENTIAL_PATTERNS, CONFIG_FILES } from './patterns';

export interface ScanFinding {
  file: string;
  line: number;
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high';
  preview: string;
}

/**
 * Scan project config files for hardcoded credentials.
 * Returns findings sorted by severity then file.
 */
export function scan(projectDir: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const configFile of CONFIG_FILES) {
    const fullPath = path.join(projectDir, configFile);
    if (!fs.existsSync(fullPath)) continue;

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > 10 * 1024 * 1024) continue;
      if (!stat.isFile()) continue;

      const content = fs.readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 4096) continue; // ReDoS protection

        // Skip env var references and placeholders
        if (/\$\{[A-Z_]+\}/.test(line) && !/sk-ant|sk-proj|AKIA|ghp_|xox[baprs]/.test(line)) {
          continue;
        }

        for (const pattern of CREDENTIAL_PATTERNS) {
          if (pattern.regex.test(line)) {
            // Mask the actual secret in the preview
            const masked = line.replace(pattern.regex, `[${pattern.name} REDACTED]`);

            findings.push({
              file: configFile,
              line: i + 1,
              patternId: pattern.id,
              patternName: pattern.name,
              severity: 'critical',
              preview: masked.trim().substring(0, 80),
            });
            break; // One finding per line
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  // Sort: critical first, then by file
  findings.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
    return a.file.localeCompare(b.file);
  });

  return findings;
}
