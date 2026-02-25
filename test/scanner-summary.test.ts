import { test } from 'node:test';
import assert from 'node:assert/strict';

const reporter = require('../src/modules/core/reporter.js');
const scanner = require('../src/modules/core/scanner.js');

test('computeSummary prioritizes critical over other severities', () => {
  const summary = reporter.computeSummary([
    { severity: 'medium' },
    { severity: 'high' },
    { severity: 'critical' },
    { severity: 'low' },
  ]);

  assert.equal(summary.riskLevel, 'critical');
  assert.equal(summary.totalIssues, 4);
  assert.equal(summary.counts.critical, 1);
  assert.equal(summary.counts.high, 1);
  assert.equal(summary.counts.medium, 1);
  assert.equal(summary.counts.low, 1);
});

test('runScan throws for unknown module names', async () => {
  await assert.rejects(async () => {
    await scanner.runScan({ module: 'unknown-module' });
  }, /Unknown module/);
});
