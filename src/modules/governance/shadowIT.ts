'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const HOME = os.homedir();

const PROCESS_PATTERNS = [
  'chatgpt', 'claude', 'cursor', 'copilot', 'ollama', 'lm studio', 'lmstudio', 'gpt4all', 'jan',
];

const BROWSER_HISTORY_PATHS = [
  path.join(HOME, '.config/google-chrome/Default/History'),
  path.join(HOME, '.config/chromium/Default/History'),
  path.join(HOME, '.mozilla/firefox'),
  path.join(HOME, '.config/microsoft-edge/Default/History'),
  path.join(HOME, 'Library/Safari/History.db'),
];

const WATCHED_DOMAINS = [
  'chat.openai.com',
  'claude.ai',
  'gemini.google.com',
  'perplexity.ai',
  'poe.com',
  'character.ai',
];

const PACKAGE_PATTERNS = ['openai', 'anthropic', 'langchain', 'ollama', 'llama', 'autogen', 'crewai', 'transformers'];

function safeExec(command) {
  try {
    return execSync(command, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000 }).toString();
  } catch {
    return '';
  }
}

function getApprovedToolsSet() {
  const raw = process.env.SCOPOS_APPROVED_AI_TOOLS || '';
  const defaults = ['copilot'];
  const userApproved = raw.split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
  return new Set([...defaults, ...userApproved]);
}

function processInventory() {
  const output = safeExec('ps -ewwo pid,user,args 2>/dev/null || ps aux 2>/dev/null').toLowerCase();
  const detected = [];

  for (const keyword of PROCESS_PATTERNS) {
    if (output.includes(keyword.toLowerCase())) {
      detected.push({ tool: keyword, source: 'process', filesystemAccess: true });
    }
  }

  return detected;
}

function browserDomainSignals() {
  const results = [];

  for (const historyPath of BROWSER_HISTORY_PATHS) {
    if (!fs.existsSync(historyPath)) continue;
    let buffer;
    try {
      const fd = fs.openSync(historyPath, 'r');
      buffer = Buffer.alloc(1024 * 1024);
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
      fs.closeSync(fd);
      const sample = buffer.slice(0, bytesRead).toString('latin1').toLowerCase();
      const domainsFound = WATCHED_DOMAINS.filter((domain) => sample.includes(domain));
      if (domainsFound.length > 0) {
        results.push({ path: historyPath, domainsFound });
      }
    } catch {
      continue;
    }
  }

  return results;
}

function installedAppsInventory() {
  const tools = [];
  const dpkg = safeExec('dpkg -l 2>/dev/null').toLowerCase();
  for (const keyword of PROCESS_PATTERNS) {
    if (dpkg.includes(keyword)) tools.push({ tool: keyword, source: 'installed-app', filesystemAccess: true });
  }
  return tools;
}

function packageInventory() {
  const detected = [];
  const npmGlobal = safeExec('npm -g ls --depth=0 --json 2>/dev/null');
  try {
    const parsed = JSON.parse(npmGlobal);
    const deps = Object.keys(parsed.dependencies || {});
    for (const dep of deps) {
      if (PACKAGE_PATTERNS.some((pattern) => dep.toLowerCase().includes(pattern))) {
        detected.push({ tool: dep, source: 'npm-global', filesystemAccess: false });
      }
    }
  } catch {
    // ignore
  }

  const pipList = safeExec('python3 -m pip list --format=json 2>/dev/null');
  try {
    const parsed = JSON.parse(pipList);
    for (const item of parsed) {
      const name = String(item.name || '').toLowerCase();
      if (PACKAGE_PATTERNS.some((pattern) => name.includes(pattern))) {
        detected.push({ tool: item.name, source: 'pip', filesystemAccess: false });
      }
    }
  } catch {
    // ignore
  }

  return detected;
}

function buildInventoryRows(entries, approvedTools) {
  const seen = new Set();
  const rows = [];

  for (const item of entries) {
    const key = `${item.source}:${item.tool.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const approved = approvedTools.has(item.tool.toLowerCase());
    rows.push({
      tool: item.tool,
      source: item.source,
      approved,
      dataAccessLevel: item.filesystemAccess ? 'filesystem' : 'limited',
    });
  }

  return rows;
}

async function run() {
  const approvedTools = getApprovedToolsSet();
  const inventory = [
    ...processInventory(),
    ...installedAppsInventory(),
    ...packageInventory(),
  ];

  const inventoryRows = buildInventoryRows(inventory, approvedTools);
  const browserSignals = browserDomainSignals();
  const findings = [];

  for (const row of inventoryRows) {
    const isHigh = !row.approved && row.dataAccessLevel === 'filesystem';
    findings.push({
      title: `Shadow AI Inventory: ${row.tool}`,
      severity: isHigh ? 'high' : 'low',
      location: row.source,
      detail: `approved=${row.approved ? 'yes' : 'no'}, dataAccessLevel=${row.dataAccessLevel}`,
      recommendation: row.approved ? 'No action required.' : 'Validate business need and move tool to approved list if legitimate.',
      tags: ['governance', 'shadow-it'],
      metadata: row,
    });
  }

  for (const signal of browserSignals) {
    findings.push({
      title: 'AI domain(s) detected in browser history artifact',
      severity: 'medium',
      location: signal.path,
      detail: `Domains found: ${signal.domainsFound.join(', ')}`,
      recommendation: 'Review acceptable-use policy and ensure approved AI services are documented.',
      tags: ['governance', 'shadow-it', 'browser-domain-signal'],
      metadata: {
        domains: signal.domainsFound,
      },
    });
  }

  return {
    name: 'Shadow IT Detector',
    findings,
    inventory: inventoryRows,
  };
}

module.exports = {
  name: 'Shadow IT Detector',
  description: 'Detect unauthorized AI tools and build a Shadow AI inventory',
  version: '0.1.0',
  run,
};

export {};
