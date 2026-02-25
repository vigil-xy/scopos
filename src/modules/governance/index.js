'use strict';

const fs = require('fs');
const path = require('path');

const shadowIT = require('./shadowIT');
const policyEnforcer = require('./policyEnforcer');
const auditAgent = require('./auditAgent');

const BUILT_INS = [shadowIT, policyEnforcer, auditAgent];

function loadCommunitySkills() {
  const skillsDir = path.join(process.cwd(), 'skills');
  if (!fs.existsSync(skillsDir)) return [];

  const files = fs.readdirSync(skillsDir)
    .filter((name) => name.endsWith('.js'))
    .map((name) => path.join(skillsDir, name));

  const loaded = [];
  for (const skillPath of files) {
    try {
      delete require.cache[require.resolve(skillPath)];
      const skill = require(skillPath);
      if (skill && typeof skill.run === 'function' && skill.name && skill.description && skill.version) {
        loaded.push(skill);
      }
    } catch {
      continue;
    }
  }
  return loaded;
}

function listSkills() {
  const community = loadCommunitySkills();
  return [...BUILT_INS, ...community].map((skill) => ({
    name: skill.name,
    description: skill.description,
    version: skill.version,
    source: BUILT_INS.includes(skill) ? 'built-in' : 'community',
  }));
}

async function runSkill(skill, context) {
  try {
    const result = await skill.run(context);
    if (Array.isArray(result)) return result;
    if (result && Array.isArray(result.findings)) return result.findings;
    return [];
  } catch (err) {
    return [{
      title: `Governance skill failed: ${skill.name}`,
      severity: 'medium',
      location: skill.name,
      detail: err.message,
      recommendation: 'Review skill implementation and runtime permissions.',
      tags: ['governance', 'skill-error'],
      metadata: { skill: skill.name },
    }];
  }
}

async function runGovernanceScan(context = {}) {
  const community = loadCommunitySkills();
  const allSkills = [...BUILT_INS, ...community];
  const findings = [];

  for (const skill of allSkills) {
    const skillFindings = await runSkill(skill, context);
    findings.push(...skillFindings.map((finding) => ({
      severity: finding.severity || 'low',
      title: finding.title || `${skill.name} finding`,
      location: finding.location || skill.name,
      detail: finding.detail || '',
      recommendation: finding.recommendation || '',
      tags: finding.tags || ['governance'],
      metadata: {
        ...(finding.metadata || {}),
        skill: skill.name,
      },
    })));
  }

  return {
    skills: allSkills.map((skill) => ({ name: skill.name, description: skill.description, version: skill.version })),
    findings,
  };
}

async function runShadowIT() {
  return shadowIT.run({ mode: 'shadow-it' });
}

module.exports = {
  listSkills,
  loadCommunitySkills,
  runGovernanceScan,
  runShadowIT,
};
