'use strict';

const shadowIT       = require('./shadowIT');
const policyEnforcer = require('./policyEnforcer');
const auditAgent     = require('./auditAgent');

async function scan() {
  const results = await Promise.all([
    shadowIT.scan(),
    policyEnforcer.scan(),
    auditAgent.scan(),
  ]);
  const findings = results.flatMap(r => r.findings || []);
  return { findings };
}

module.exports = { scan };