'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');
const BASE_DIR = path.join(os.homedir(), '.scopos');
const POLICY_DIR = path.join(BASE_DIR, 'policy');
const VIOLATION_LOG = path.join(POLICY_DIR, 'violations.jsonl');
const LLM_ENDPOINTS = [
    'api.openai.com',
    'api.anthropic.com',
    'generativelanguage.googleapis.com',
    'api.cohere.ai',
];
const PII_PATTERNS = [
    { type: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
    { type: 'phone', re: /\+?[0-9][0-9\s().-]{7,}[0-9]/ },
    { type: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/ },
    { type: 'credit-card', re: /\b(?:\d[ -]*?){13,19}\b/ },
    { type: 'name-account-adjacent', re: /\b(name|customer|user)\b.{0,20}\b(account|acct|iban)\b/i },
    { type: 'ip-address', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
];
function ensureDirs() {
    if (!fs.existsSync(BASE_DIR))
        fs.mkdirSync(BASE_DIR, { recursive: true });
    if (!fs.existsSync(POLICY_DIR))
        fs.mkdirSync(POLICY_DIR, { recursive: true });
}
function detectPiiTypes(text) {
    const lower = String(text || '');
    const found = [];
    for (const rule of PII_PATTERNS) {
        if (rule.re.test(lower))
            found.push(rule.type);
    }
    return found;
}
function appendViolation(entry) {
    ensureDirs();
    fs.appendFileSync(VIOLATION_LOG, `${JSON.stringify(entry)}\n`, 'utf8');
}
function processSnapshot() {
    try {
        return execSync('ps -ewwo pid,args 2>/dev/null || ps aux 2>/dev/null', {
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
        }).toString();
    }
    catch {
        return '';
    }
}
function detectViolationsFromSnapshot(snapshot) {
    const violations = [];
    const lines = snapshot.split('\n').slice(1);
    for (const line of lines) {
        const lower = line.toLowerCase();
        const endpoint = LLM_ENDPOINTS.find((domain) => lower.includes(domain));
        if (!endpoint)
            continue;
        const piiTypes = detectPiiTypes(line);
        if (!piiTypes.length)
            continue;
        const parts = line.trim().split(/\s+/);
        const app = parts.slice(1, 3).join(' ') || 'unknown-process';
        violations.push({
            timestamp: new Date().toISOString(),
            destinationApi: endpoint,
            piiTypes,
            application: app,
        });
    }
    return violations;
}
function readViolations() {
    ensureDirs();
    if (!fs.existsSync(VIOLATION_LOG))
        return [];
    const lines = fs.readFileSync(VIOLATION_LOG, 'utf8').split('\n').filter(Boolean);
    const parsed = [];
    for (const line of lines) {
        try {
            parsed.push(JSON.parse(line));
        }
        catch {
            continue;
        }
    }
    return parsed;
}
function getViolationsLast24h() {
    const since = Date.now() - (24 * 60 * 60 * 1000);
    return readViolations().filter((item) => new Date(item.timestamp).getTime() >= since);
}
function generateDailyReport() {
    const all = readViolations();
    const byDate = {};
    for (const entry of all) {
        const date = String(entry.timestamp).slice(0, 10);
        if (!byDate[date])
            byDate[date] = [];
        byDate[date].push(entry);
    }
    return Object.entries(byDate).map(([date, entries]) => ({
        date,
        totalViolations: entries.length,
        byDestination: entries.reduce((acc, item) => {
            acc[item.destinationApi] = (acc[item.destinationApi] || 0) + 1;
            return acc;
        }, {}),
        piiTypes: [...new Set(entries.flatMap((item) => item.piiTypes || []))],
    }));
}
async function startWatchMode() {
    ensureDirs();
    const timer = setInterval(() => {
        const snapshot = processSnapshot();
        const violations = detectViolationsFromSnapshot(snapshot);
        for (const violation of violations) {
            appendViolation(violation);
            process.stdout.write(`[policy] violation: ${violation.destinationApi} (${violation.piiTypes.join(', ')}) by ${violation.application}\n`);
        }
    }, 5000);
    await new Promise((resolve) => {
        process.on('SIGINT', () => {
            clearInterval(timer);
            resolve();
        });
        process.on('SIGTERM', () => {
            clearInterval(timer);
            resolve();
        });
    });
}
async function run() {
    const last24 = getViolationsLast24h();
    if (!last24.length) {
        return {
            findings: [{
                    title: 'No PII policy violations detected in last 24 hours',
                    severity: 'low',
                    location: VIOLATION_LOG,
                    detail: 'No outbound LLM request patterns with detectable PII were logged.',
                    recommendation: 'Continue monitoring.',
                    tags: ['governance', 'pii-policy'],
                }],
        };
    }
    return {
        findings: [{
                title: 'PII policy violations detected',
                severity: 'high',
                location: VIOLATION_LOG,
                detail: `${last24.length} violation(s) in last 24 hours.`,
                recommendation: 'Investigate violating applications and enforce outbound policy controls.',
                tags: ['governance', 'pii-policy'],
                metadata: {
                    violationsLast24h: last24.length,
                    dailyReport: generateDailyReport(),
                },
            }],
    };
}
module.exports = {
    name: 'Policy Enforcer',
    description: 'Monitors and reports potential PII exposure to LLM APIs',
    version: '0.1.0',
    startWatchMode,
    getViolationsLast24h,
    generateDailyReport,
    run,
};
