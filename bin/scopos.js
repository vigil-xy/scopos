#!/usr/bin/env node
'use strict';

const path    = require('path');
const fs      = require('fs');
const os      = require('os');

const aiSurface  = require('../src/modules/ai-surface');
const governance = require('../src/modules/governance');
const auditChain = require('../src/modules/governance/auditAgent');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ICONS = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

function printFinding(f) {
  const icon = ICONS[f.severity] || '⚪';
  const title = f.title || f.message || '(no title)';
  console.log(`  ${icon} [${(f.severity || 'info').toUpperCase()}] ${title}`);
  if (f.location) console.log(`     Location   : ${f.location}`);
  if (f.detail)   console.log(`     Detail     : ${f.detail}`);
  if (f.recommendation) console.log(`     Recommend  : ${f.recommendation}`);
}

async function runScan(opts = {}) {
  console.log('\n🔍  scopos — AI attack surface scanner\n');

  const [aiResults, govResults] = await Promise.all([
    aiSurface.scan(),
    governance.scan(),
  ]);

  const allFindings = [
    ...aiResults.findings,
    ...govResults.findings,
  ].sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  if (allFindings.length === 0) {
    console.log('  ✅  No findings. Environment looks clean.\n');
  } else {
    console.log(`  Found ${allFindings.length} finding(s):\n`);
    for (const f of allFindings) printFinding(f);
    console.log();
  }

  console.log('Summary:', Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `${ICONS[k]} ${v} ${k}`)
    .join('  ') || 'none');
  console.log();

  // Record to audit chain
  await auditChain.record({ findings: allFindings });

  if (opts.output) {
    const report = { timestamp: new Date().toISOString(), findings: allFindings, summary: counts };
    fs.writeFileSync(opts.output, JSON.stringify(report, null, 2));
    console.log(`📄  Report written to ${opts.output}\n`);
  }

  return allFindings;
}

async function runAudit() {
  console.log('\n🔒  Verifying tamper-evident audit chain…\n');
  const result = await auditChain.verify();
  if (result.valid) {
    console.log(`  ✅  Chain is intact. ${result.entries} entries verified.\n`);
  } else {
    console.error(`  ❌  Chain TAMPERED at entry ${result.failedAt}: ${result.reason}\n`);
    process.exitCode = 1;
  }
}

// ── CLI ─────────────────────────────────────────────────────────────────────
const [,, cmd, ...rest] = process.argv;

(async () => {
  switch (cmd) {
    case 'scan': {
      const outFlag = rest.indexOf('-o');
      const output  = outFlag !== -1 ? rest[outFlag + 1] : null;
      await runScan({ output });
      break;
    }
    case 'audit':
      await runAudit();
      break;
    default:
      console.log('Usage: node bin/scopos.js scan [-o report.json]');
      console.log('       node bin/scopos.js audit');
      process.exitCode = 1;
  }
})();
