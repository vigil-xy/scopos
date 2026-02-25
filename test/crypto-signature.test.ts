import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function withTempHome<T>(fn: () => T): T {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scopos-home-'));
  const originalHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    return fn();
  } finally {
    if (originalHome) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

test('signs and verifies a report payload with Ed25519', () => {
  withTempHome(() => {
    const cryptoModule = require('../src/modules/core/crypto.js');

    const reportPayload = {
      metadata: { timestamp: new Date().toISOString(), hostname: 'test-host' },
      summary: { riskLevel: 'low', totalIssues: 0, counts: { critical: 0, high: 0, medium: 0, low: 0 } },
      modules: {},
      governance: { title: 'GOVERNANCE MODULES', findings: [] },
    };

    const signature = cryptoModule.signReportPayload(reportPayload);
    const verify = cryptoModule.verifySignedReport({ report: reportPayload, signature });

    assert.equal(signature.algorithm, 'Ed25519');
    assert.equal(typeof signature.hash, 'string');
    assert.equal(typeof signature.signature, 'string');
    assert.equal(verify.ok, true);
  });
});
