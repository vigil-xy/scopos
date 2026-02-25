'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const { globSync } = require('glob');

const KEY_PATTERNS = [
  { keyType: 'OpenAI', re: /sk-[a-zA-Z0-9]{48}/g },
  { keyType: 'Anthropic', re: /sk-ant-[a-zA-Z0-9\-]{90,}/g },
  { keyType: 'Google Gemini', re: /AIza[0-9A-Za-z\-_]{35}/g },
  { keyType: 'Cohere', re: /\b[a-zA-Z0-9]{40}\b/g, requireContext: true },
  { keyType: 'HuggingFace', re: /hf_[a-zA-Z0-9]{34}/g },
  { keyType: 'Mistral', re: /\b[a-zA-Z0-9]{32}\b/g, requireContext: true },
  { keyType: 'Replicate', re: /r8_[a-zA-Z0-9]{40}/g },
];

const HOME = os.homedir();

function maskSecret(secret) {
  if (!secret || secret.length < 8) return '[masked]';
  return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}

function addFinding(findings, key, value) {
  const fingerprint = `${value.filePath}:${value.keyType}:${value.sample}`;
  if (findings.seen.has(fingerprint)) return;
  findings.seen.add(fingerprint);
  findings.items.push({
    title: `${value.keyType} API key exposure`,
    severity: 'critical',
    location: value.filePath,
    detail: `Detected ${value.keyType} key pattern (${value.sample})`,
    recommendation: 'Remove key from file, rotate credential, and use a secrets manager.',
    tags: ['api-key', 'credential-exposure'],
    metadata: {
      keyType: value.keyType,
      appearsInGitHistory: Boolean(value.inGitHistory),
      source: value.source,
    },
  });
}

function hasKeyContext(content, match, index) {
  const start = Math.max(0, index - 80);
  const end = Math.min(content.length, index + match.length + 80);
  const window = content.slice(start, end).toLowerCase();
  return /(api[_-]?key|cohere|mistral|token|secret|authorization)/i.test(window);
}

function scanContent(content, filePath, source, inGitHistory = false) {
  const findings = [];
  for (const { keyType, re, requireContext } of KEY_PATTERNS) {
    const scoped = new RegExp(re.source, re.flags);
    const matches = [...content.matchAll(scoped)];
    for (const matched of matches.slice(0, 5)) {
      const hit = matched[0];
      const index = matched.index || 0;
      if (requireContext && !hasKeyContext(content, hit, index)) continue;
      findings.push({
        filePath,
        keyType,
        sample: maskSecret(hit),
        inGitHistory,
        source,
      });
    }
  }
  return findings;
}

function safeReadText(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return '';
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function getTargetFiles() {
  const root = process.cwd();
  const targets = new Set([
    path.join(root, '.env'),
    path.join(root, '.env.local'),
    path.join(root, '.env.production'),
    path.join(root, '.env.development'),
    path.join(HOME, '.zshrc'),
    path.join(HOME, '.bashrc'),
    path.join(HOME, '.bash_profile'),
    path.join(HOME, '.profile'),
  ]);

  const configFiles = globSync('*.{json,yaml,yml,toml}', { cwd: root, absolute: true, nodir: true });
  const homeConfigFiles = globSync('**/*', {
    cwd: path.join(HOME, '.config'),
    absolute: true,
    nodir: true,
    maxDepth: 3,
  });

  for (const filePath of configFiles) targets.add(filePath);
  for (const filePath of homeConfigFiles) targets.add(filePath);

  return [...targets].filter((candidate) => fs.existsSync(candidate));
}

function scanGitHistory() {
  try {
    const output = execSync('git --no-pager log -n 20 -p -- .', {
      cwd: process.cwd(),
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 12000,
    }).toString();
    return scanContent(output, 'git://history:last-20-commits', 'git-history', true);
  } catch {
    return [];
  }
}

async function scan() {
  const collector = { items: [], seen: new Set() };

  for (const filePath of getTargetFiles()) {
    const content = safeReadText(filePath);
    if (!content) continue;
    const fileFindings = scanContent(content, filePath, 'filesystem', false);
    for (const finding of fileFindings) {
      addFinding(collector, `${finding.filePath}:${finding.keyType}:${finding.sample}`, finding);
    }
  }

  const gitFindings = scanGitHistory();
  for (const finding of gitFindings) {
    addFinding(collector, `${finding.filePath}:${finding.keyType}:${finding.sample}`, finding);
  }

  return { findings: collector.items };
}

module.exports = { scan };