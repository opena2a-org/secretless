/**
 * Auto-detect which AI tools are present in a project.
 */

import * as fs from 'fs';
import * as path from 'path';

export type AITool = 'claude-code' | 'cursor' | 'copilot' | 'windsurf' | 'cline' | 'aider';

interface DetectionResult {
  tool: AITool;
  configDir: string;
  settingsFile: string;
  hooksSupported: boolean;
}

const DETECTORS: Array<{
  tool: AITool;
  markers: string[];
  configDir: string;
  settingsFile: string;
  hooksSupported: boolean;
}> = [
  {
    tool: 'claude-code',
    markers: ['.claude', 'CLAUDE.md', '.claude/settings.json'],
    configDir: '.claude',
    settingsFile: '.claude/settings.json',
    hooksSupported: true,
  },
  {
    tool: 'cursor',
    markers: ['.cursor', '.cursorrules', '.cursor/rules'],
    configDir: '.cursor',
    settingsFile: '.cursor/settings.json',
    hooksSupported: false,
  },
  {
    tool: 'copilot',
    markers: ['.github/copilot-instructions.md', '.copilot'],
    configDir: '.github',
    settingsFile: '.github/copilot-instructions.md',
    hooksSupported: false,
  },
  {
    tool: 'windsurf',
    markers: ['.windsurfrules', '.windsurf'],
    configDir: '.windsurf',
    settingsFile: '.windsurfrules',
    hooksSupported: false,
  },
  {
    tool: 'cline',
    markers: ['.clinerules', '.cline'],
    configDir: '.cline',
    settingsFile: '.clinerules',
    hooksSupported: false,
  },
  {
    tool: 'aider',
    markers: ['.aider.conf.yml', '.aiderignore'],
    configDir: '.',
    settingsFile: '.aider.conf.yml',
    hooksSupported: false,
  },
];

/**
 * Detect AI tools present in the project directory.
 * Returns all detected tools sorted by priority (hooks-capable first).
 */
export function detectAITools(projectDir: string): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const detector of DETECTORS) {
    const found = detector.markers.some(marker => {
      const fullPath = path.join(projectDir, marker);
      return fs.existsSync(fullPath);
    });

    if (found) {
      results.push({
        tool: detector.tool,
        configDir: detector.configDir,
        settingsFile: detector.settingsFile,
        hooksSupported: detector.hooksSupported,
      });
    }
  }

  // Sort: hooks-capable tools first
  results.sort((a, b) => {
    if (a.hooksSupported && !b.hooksSupported) return -1;
    if (!a.hooksSupported && b.hooksSupported) return 1;
    return 0;
  });

  return results;
}

/** Get display name for a tool */
export function toolDisplayName(tool: AITool): string {
  const names: Record<AITool, string> = {
    'claude-code': 'Claude Code',
    'cursor': 'Cursor',
    'copilot': 'GitHub Copilot',
    'windsurf': 'Windsurf',
    'cline': 'Cline',
    'aider': 'Aider',
  };
  return names[tool];
}
