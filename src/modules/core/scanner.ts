'use strict';

const os = require('os');

const apikeys = require('../ai-surface/apikeys');
const mcp = require('../ai-surface/mcp');
const agents = require('../ai-surface/agents');
const models = require('../ai-surface/models');
const endpoints = require('../ai-surface/endpoints');
const governance = require('../governance');

const MODULES = {
  apikeys: {
    title: 'LLM API KEY EXPOSURE',
    run: () => apikeys.scan(),
  },
  mcp: {
    title: 'MCP SERVER SECURITY',
    run: () => mcp.scan(),
  },
  agents: {
    title: 'AI AGENT PROCESSES',
    run: () => agents.scan(),
  },
  models: {
    title: 'MODEL FILE INTEGRITY',
    run: () => models.scan(),
  },
  endpoints: {
    title: 'INFERENCE ENDPOINT EXPOSURE',
    run: () => endpoints.scan(),
  },
};

function normalizeFindings(moduleName: string, findings: any[]) {
  return (findings || []).map((finding) => ({
    module: moduleName,
    severity: finding.severity || 'low',
    title: finding.title || finding.message || 'Issue detected',
    location: finding.location || finding.detail || 'N/A',
    detail: finding.detail || '',
    recommendation: finding.recommendation || '',
    tags: finding.tags || [],
    metadata: finding.metadata || {},
  }));
}

async function runScan(options: { module?: string | null } = {}) {
  const selectedModule = options.module || null;
  const moduleNames = selectedModule ? [selectedModule] : Object.keys(MODULES);

  const results = {};
  const allFindings = [];

  for (const moduleName of moduleNames) {
    if (!MODULES[moduleName]) {
      throw new Error(`Unknown module: ${moduleName}`);
    }

    const raw = await MODULES[moduleName].run();
    const normalized = normalizeFindings(moduleName, raw.findings || raw);
    results[moduleName] = {
      id: moduleName,
      title: MODULES[moduleName].title,
      findings: normalized,
    };
    allFindings.push(...normalized);
  }

  let governanceResult: { title: string; findings: any[]; skills?: any[] } = { title: 'GOVERNANCE MODULES', findings: [] };
  if (!selectedModule) {
    const governanceScan = await governance.runGovernanceScan();
    governanceResult = {
      title: 'GOVERNANCE MODULES',
      findings: normalizeFindings('governance', governanceScan.findings || []),
      skills: governanceScan.skills || [],
    };
    allFindings.push(...governanceResult.findings);
  }

  return {
    metadata: {
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
    },
    modules: results,
    governance: governanceResult,
    findings: allFindings,
  };
}

module.exports = {
  MODULES,
  runScan,
};

export {};
