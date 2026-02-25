'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const cryptoModule = require('./crypto');
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
function severityLabel(level) {
    switch (level) {
        case 'critical': return '🔴 CRITICAL';
        case 'high': return '🟠 HIGH';
        case 'medium': return '🟡 MEDIUM';
        default: return '🟢 LOW';
    }
}
function computeSummary(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of findings) {
        const sev = (finding.severity || 'low').toLowerCase();
        if (counts[sev] !== undefined)
            counts[sev] += 1;
    }
    let riskLevel = 'low';
    if (counts.critical > 0)
        riskLevel = 'critical';
    else if (counts.high > 0)
        riskLevel = 'high';
    else if (counts.medium > 0)
        riskLevel = 'medium';
    return {
        riskLevel,
        totalIssues: counts.critical + counts.high + counts.medium + counts.low,
        counts,
    };
}
function formatFindings(findings) {
    if (!findings || !findings.length)
        return 'No findings.';
    return findings
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
        .map((f) => {
        const sev = (f.severity || 'low').toUpperCase();
        return `- [${sev}] ${f.title} (${f.location})`;
    })
        .join('\n');
}
function section(title, body = '') {
    return [
        '─────────────────────────────────────────────────────────────',
        title.padStart(Math.floor((61 + title.length) / 2), ' '),
        '─────────────────────────────────────────────────────────────',
        body,
        '',
    ].join('\n');
}
function buildReport(scanResult) {
    const summary = computeSummary(scanResult.findings || []);
    return {
        metadata: scanResult.metadata,
        summary,
        modules: scanResult.modules,
        governance: scanResult.governance,
    };
}
function signReport(scanResult) {
    const report = buildReport(scanResult);
    const signature = cryptoModule.signReportPayload(report);
    return { report, signature };
}
function renderTextReport(signedReport) {
    const report = signedReport.report;
    const summary = report.summary;
    const modules = report.modules || {};
    return [
        '═══════════════════════════════════════════════════════════════',
        '                    SCOPOS AI SECURITY SCAN                    ',
        '═══════════════════════════════════════════════════════════════',
        '',
        `Timestamp: ${report.metadata.timestamp}`,
        `Hostname:  ${report.metadata.hostname}`,
        '',
        section('SUMMARY', [
            `Risk Level:      ${severityLabel(summary.riskLevel)}`,
            `Total Issues:    ${summary.totalIssues}`,
            `  Critical:      ${summary.counts.critical}`,
            `  High:          ${summary.counts.high}`,
            `  Medium:        ${summary.counts.medium}`,
            `  Low:           ${summary.counts.low}`,
        ].join('\n')),
        section('LLM API KEY EXPOSURE', formatFindings(modules.apikeys?.findings || [])),
        section('MCP SERVER SECURITY', formatFindings(modules.mcp?.findings || [])),
        section('AI AGENT PROCESSES', formatFindings(modules.agents?.findings || [])),
        section('MODEL FILE INTEGRITY', formatFindings(modules.models?.findings || [])),
        section('INFERENCE ENDPOINT EXPOSURE', formatFindings(modules.endpoints?.findings || [])),
        section('GOVERNANCE MODULES', formatFindings(report.governance?.findings || [])),
        '═══════════════════════════════════════════════════════════════',
        '                       END OF REPORT                          ',
        '═══════════════════════════════════════════════════════════════',
        '',
        '─────────────────────────────────────────────────────────────',
        '                  CRYPTOGRAPHIC SIGNATURE                     ',
        '─────────────────────────────────────────────────────────────',
        `Algorithm: ${signedReport.signature.algorithm}`,
        `Hash (SHA-256): ${signedReport.signature.hash}`,
        `Signature: ${signedReport.signature.signature}`,
        `Public Key Location: ${signedReport.signature.publicKeyLocation}`,
    ].join('\n');
}
module.exports = {
    buildReport,
    signReport,
    renderTextReport,
    computeSummary,
};
