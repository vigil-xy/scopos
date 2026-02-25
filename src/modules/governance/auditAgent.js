'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const cron = require('node-cron');

const scanner = require('../core/scanner');
const reporter = require('../core/reporter');
const policyEnforcer = require('./policyEnforcer');

const BASE_DIR = path.join(os.homedir(), '.scopos');
const REPORTS_DIR = path.join(BASE_DIR, 'reports');
const HISTORY_FILE = path.join(BASE_DIR, 'audit-history.json');

function ensureDirs() {
  if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

function getHistory() {
  ensureDirs();
  if (!fs.existsSync(HISTORY_FILE)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveHistory(items) {
  ensureDirs();
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(items, null, 2), 'utf8');
}

function criterionPassed(findings, matcher) {
  return findings.filter(matcher).length === 0;
}

function calculateReadiness(scanResult) {
  const findings = scanResult.findings || [];
  const piiViolations = policyEnforcer.getViolationsLast24h().length;

  const checks = {
    noExposedApiKeys: criterionPassed(findings, (f) => f.module === 'apikeys' && f.severity === 'critical'),
    noPublicEndpoints: criterionPassed(findings, (f) => (f.tags || []).includes('public-exposure')),
    noUnauthorizedElevatedAgents: criterionPassed(findings, (f) => (f.tags || []).includes('elevated-privilege')),
    noPiiViolationsLast24h: piiViolations === 0,
    allModelFilesVerified: criterionPassed(findings, (f) => (f.tags || []).includes('unverified')),
  };

  const breakdown = {
    noExposedApiKeys: checks.noExposedApiKeys ? 25 : 0,
    noPublicEndpoints: checks.noPublicEndpoints ? 20 : 0,
    noUnauthorizedElevatedAgents: checks.noUnauthorizedElevatedAgents ? 20 : 0,
    noPiiViolationsLast24h: checks.noPiiViolationsLast24h ? 20 : 0,
    allModelFilesVerified: checks.allModelFilesVerified ? 15 : 0,
  };

  const score = Object.values(breakdown).reduce((acc, value) => acc + value, 0);
  return {
    score,
    breakdown,
    checks,
    piiViolationsLast24h: piiViolations,
  };
}

async function runMorningAudit() {
  ensureDirs();
  const scan = await scanner.runScan();
  const signedReport = reporter.signReport(scan);
  const readiness = calculateReadiness(scan);

  const date = new Date().toISOString().slice(0, 10);
  const reportPath = path.join(REPORTS_DIR, `${date}.json`);
  fs.writeFileSync(reportPath, JSON.stringify({ ...signedReport, readiness }, null, 2), 'utf8');

  const history = getHistory().filter((item) => item.date !== date);
  history.push({
    date,
    score: readiness.score,
    breakdown: readiness.breakdown,
    reportPath,
    timestamp: new Date().toISOString(),
  });

  history.sort((a, b) => a.date.localeCompare(b.date));
  saveHistory(history);

  return {
    date,
    score: readiness.score,
    breakdown: readiness.breakdown,
    reportPath,
  };
}

async function getTodayScore(runIfMissing = false) {
  const date = new Date().toISOString().slice(0, 10);
  const history = getHistory();
  const existing = history.find((item) => item.date === date);
  if (existing) return existing;
  if (runIfMissing) return runMorningAudit();
  return { date, score: null, breakdown: null, reportPath: null };
}

async function startDaemon() {
  ensureDirs();
  cron.schedule('0 6 * * *', async () => {
    try {
      const result = await runMorningAudit();
      process.stdout.write(`[audit-daemon] readiness score ${result.score} for ${result.date}\n`);
    } catch (err) {
      process.stderr.write(`[audit-daemon] failed: ${err.message}\n`);
    }
  });

  await new Promise((resolve) => {
    process.on('SIGINT', resolve);
    process.on('SIGTERM', resolve);
  });
}

async function run() {
  const score = await getTodayScore(false);
  const hasScore = score && typeof score.score === 'number';
  return {
    findings: [{
      title: hasScore ? `Readiness Score: ${score.score}` : 'No readiness score available for today',
      severity: hasScore && score.score < 70 ? 'medium' : 'low',
      location: HISTORY_FILE,
      detail: hasScore ? `Breakdown: ${JSON.stringify(score.breakdown)}` : 'Run scopos audit --score to calculate today\'s readiness score.',
      recommendation: hasScore ? 'Track trend daily and remediate low-scoring controls.' : 'Start audit daemon or run daily score command.',
      tags: ['governance', 'audit-agent'],
      metadata: score,
    }],
  };
}

module.exports = {
  name: 'Automated Audit Agent',
  description: 'Calculates and tracks daily Scopos readiness score',
  version: '0.1.0',
  startDaemon,
  runMorningAudit,
  getTodayScore,
  getHistory,
  run,
};
