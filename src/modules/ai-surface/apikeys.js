'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const KEY_PATTERNS = [
  { name: 'OpenAI',    re: /sk-[A-Za-z0-9]{20,}/ },
  { name: 'Anthropic', re: /sk-ant-[A-Za-z0-9\-]{20,}/ },
  { name: 'Cohere',    re: /[A-Za-z0-9]{40}/ },
  { name: 'HuggingFace', re: /hf_[A-Za-z0-9]{30,}/ },
  { name: 'Replicate', re: /r8_[A-Za-z0-9]{30,}/ },
];

const SCAN_TARGETS = [
  path.join(os.homedir(), '.env'),
  path.join(os.homedir(), '.bashrc'),
  path.join(os.homedir(), '.zshrc'),
  path.join(os.homedir(), '.profile'),
  path.join(os.homedir(), '.bash_history'),
  path.join(os.homedir(), '.zsh_history'),
  '.env',
  '.env.local',
  '.env.production',
];

function scanFile(filePath) {
  if (!fs.existsSync(filePath)) return [];
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); }
  catch { return []; }
  const findings = [];
  for (const { name, re } of KEY_PATTERNS) {
    if (re.test(content)) {
      findings.push({
        severity: 'critical',
        message:  `Potential ${name} API key found`,
        detail:   `File: ${filePath}`,
      });
    }
  }
  return findings;
}

async function scan() {
  const findings = SCAN_TARGETS.flatMap(scanFile);
  return { findings };
}

module.exports = { scan };