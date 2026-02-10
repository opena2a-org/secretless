/**
 * Check Secretless AI protection status for a project.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, type AITool } from './detect';
import { scan } from './scan';

export interface StatusResult {
  isProtected: boolean;
  configuredTools: AITool[];
  hookInstalled: boolean;
  denyRuleCount: number;
  secretsFound: number;
}

/**
 * Check the current protection status of the project.
 */
export function status(projectDir: string): StatusResult {
  const result: StatusResult = {
    isProtected: false,
    configuredTools: [],
    hookInstalled: false,
    denyRuleCount: 0,
    secretsFound: 0,
  };

  // Check Claude Code hook
  const hookPath = path.join(projectDir, '.claude', 'hooks', 'secretless-guard.sh');
  result.hookInstalled = fs.existsSync(hookPath);

  // Check Claude Code deny rules
  const settingsPath = path.join(projectDir, '.claude', 'settings.json');
  if (fs.existsSync(settingsPath)) {
    try {
      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      result.denyRuleCount = settings?.permissions?.deny?.length || 0;
    } catch {
      // Invalid JSON
    }
  }

  // Check which tools have Secretless AI instructions
  const detected = detectAITools(projectDir);
  for (const tool of detected) {
    const filePath = path.join(projectDir, tool.settingsFile);
    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        if (content.includes('secretless:managed') || content.includes('Secretless AI')) {
          result.configuredTools.push(tool.tool);
        }
      } catch {
        // Skip
      }
    }
  }

  // Also check CLAUDE.md directly
  const claudeMd = path.join(projectDir, 'CLAUDE.md');
  if (fs.existsSync(claudeMd)) {
    try {
      const content = fs.readFileSync(claudeMd, 'utf-8');
      if (content.includes('secretless:managed') && !result.configuredTools.includes('claude-code')) {
        result.configuredTools.push('claude-code');
      }
    } catch {
      // Skip
    }
  }

  // Scan for secrets (project-level only for status report)
  const findings = scan(projectDir, { scanGlobal: false });
  result.secretsFound = findings.length;

  // Protected if hook is installed OR instructions are present in at least one tool
  result.isProtected = result.hookInstalled || result.configuredTools.length > 0;

  return result;
}
